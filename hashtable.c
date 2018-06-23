/*
 * Copyright (c) 2018 Steven Lee <geekerlw@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 */

#include <linux/string.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/slab.h>

#define HASH_TABLE_SIZE	(8)
#define HASH_KEY_MAX_LEN	(256)
#define HASH_VALUE_MAX_LEN	(512)
#define MAX_BUF_SIZE (HASH_KEY_MAX_LEN + HASH_VALUE_MAX_LEN + 16)

#define sys_call_num (223)

typedef char* hash_key_t;
typedef char* hash_value_t;

typedef struct ht_data{
	hash_key_t key;
	hash_value_t value;
	struct hlist_node hnode;
}ht_data_t;

struct hlist_head g_hash_table[HASH_TABLE_SIZE];

static unsigned long *g_syscall_addr[3];
static unsigned long **g_syscall_table_addr;

static const char *proc_node_name = "hashtable";
static struct proc_dir_entry *proc_node_entry;

static char proc_msg[MAX_BUF_SIZE];;

// BKDRHash
static unsigned int ht_hash_create(hash_key_t key)
{
	unsigned int seed = 131;
	register unsigned int hash = 0;

	while(*key) {
		hash = hash * seed + (*key++);
	}

	return (hash & 0x7FFFFFFF) % HASH_TABLE_SIZE;
}

// get the bucket index and current node by key
static bool ht_search_by_key(const hash_key_t key, unsigned int *ht_bucket_index, ht_data_t **data)
{
	ht_data_t *tmp_data;

	// get the hash bucket index
	unsigned int index = ht_hash_create(key);

	hlist_for_each_entry(tmp_data, g_hash_table + index, hnode) {
		if(strncmp(key, tmp_data->key, strlen(key)) == 0) {
			break;
		}
	}

	*ht_bucket_index = index;
	*data = tmp_data;

	return tmp_data != NULL;
}

void ht_data_add(const hash_key_t key, const hash_value_t value)
{
	unsigned int index;
	ht_data_t *data;

	// find if the node is exist
	if(ht_search_by_key(key, &index, &data)) {
		// the key is already exist, update it ?
		data->value = value;
		return;
	}

	// if not find exist node, copy as a new node
	data = (ht_data_t *)kmalloc(sizeof(ht_data_t), GFP_KERNEL);
	data->key = (char *) kmalloc(sizeof(char) * (strlen(key) + 1), GFP_KERNEL);
	data->value = (char *) kmalloc(sizeof(char) * (strlen(value) + 1), GFP_KERNEL);

	if(data == NULL || data->key == NULL || data->value == NULL) {
		printk("hashtable: kmalloc failed\n");
		return;
	}

	memcpy(data->key, key, (strlen(key) + 1));
	memcpy(data->value, value, (strlen(value) + 1));

	INIT_HLIST_NODE(&(data->hnode));

	// add the node to the hlist
	hlist_add_head(&(data->hnode), g_hash_table + index);  // index: table bucket index

	return;
}
EXPORT_SYMBOL(ht_data_add);

void ht_data_remove(const hash_key_t key)
{
	unsigned int index;
	ht_data_t *data;

	if(!ht_search_by_key(key, &index, &data)) {
		return;
	}

	hlist_del_init(&(data->hnode));

	kfree(data->key);
	data->key = NULL;
	kfree(data->value);
	data->value = NULL;
	kfree(data);
	data = NULL;

	return;
}
EXPORT_SYMBOL(ht_data_remove);


// query the value of the key
int ht_data_query(const hash_key_t key, hash_value_t *value) {
	unsigned int index;
	ht_data_t *data;

	if(!ht_search_by_key(key, &index, &data)) {
		return -1;
	}

	*value = data->value;

	return 0;
}
EXPORT_SYMBOL(ht_data_query);

static void syscall_addr_rw(unsigned long address)
{
	unsigned int level;
	pte_t *p = lookup_address(address, &level);
	if(p->pte & ~_PAGE_RW) {
		p->pte |= _PAGE_RW;
	}

	return;
}

static void syscall_addr_ro(unsigned long address)
{
	unsigned int level;
	pte_t *p = lookup_address(address, &level);
	p->pte &= ~_PAGE_RW;

	return;
}

static unsigned long **syscall_table_address_get(void)
{
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;

	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;

		if (sct[__NR_close] == (unsigned long *) ksys_close)
			return sct;

		offset += sizeof(void *);
	}

	return NULL;
}

static int syscall_init_module(void)
{
	g_syscall_table_addr = syscall_table_address_get();
	if (g_syscall_table_addr == NULL) {
		printk("hashtable: failed to get sys call table address\n");
		return -1;
	}

	return 0;
}

static int syscall_cleanup_module(void)
{

	return 0;
}

// read proc in user space
static ssize_t proc_node_read(struct file *file, char __user *buffer, size_t count, loff_t *pos)
{
	ssize_t len = strlen(proc_msg);

	return simple_read_from_buffer(buffer, count, pos, proc_msg, len);
}

// write proc in user space
static ssize_t proc_node_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
	char msg[MAX_BUF_SIZE] = { 0 };
	char args[MAX_BUF_SIZE] = { 0 };
	ssize_t len;
	const char *delim = " ";
	hash_key_t key;
	hash_value_t value;
	char *s, *p = NULL;

	// clear proc msg
	memset(proc_msg, 0, sizeof(proc_msg));

	len = simple_write_to_buffer(msg, sizeof(msg), pos, buffer, count);
	memcpy(args, msg + 4, count - 5); // no need '\n'
	s = args;

	// add key-value
	if(strncmp(msg, "add", strlen("add")) == 0) {
		for(p = strsep(&s, delim); p != NULL; p = strsep(&s, delim)) {
			key = p;
			value = strsep(&s, delim);
			printk("hashtable: add key: %s, value: %s\n", key, value);
			ht_data_add(key, value);
			sprintf(proc_msg, "add key: %s, value: %s\n", key, value);
		}
	}
	// delete key
	else if (strncmp("del", msg, strlen("del")) == 0) {
		for(p = strsep(&s, delim); p != NULL; p = strsep(&s, delim)) {
			key = p;
			printk("hashtable: del key: %s\n", key);
			ht_data_remove(key);
			sprintf(proc_msg, "del key: %s\n", key);
		}
	}
	// query key
	else if (strncmp("get", msg, strlen("get")) == 0) {
		for(p = strsep(&s, delim); p != NULL; p = strsep(&s, delim)) {
			char *value;
			key = p;
			if(ht_data_query(key, &value) == 0 ) {
				printk("hashtable: found the key: %s, value: %s\n", key, value);
				sprintf(proc_msg, "query out the key: %s, value: %s\n", key, value);
			} else {
				printk("hashtable: not found the key: %s\n", key);
				sprintf(proc_msg, "query failed, no such key: %s\n", key);
			}
		}
	}

	return len;
}

static struct file_operations proc_node_fops = {
	.read = proc_node_read,
	.write = proc_node_write,
};

static int __init hashtable_init(void)
{
	unsigned int i;

	// hash table bucket init	
	for(i = 0; i < HASH_TABLE_SIZE; i++) {
		INIT_HLIST_HEAD(g_hash_table + i);
	}

	// system call replace
	//syscall_init_module();

	// procfs node create
	if((proc_node_entry = proc_create(proc_node_name, S_IFREG | S_IRUGO | S_IWUGO, NULL, &proc_node_fops)) == NULL) {
		printk("hashtable: failed to create proc fs node: %s\n", proc_node_name);
		return 0;
	}
	
	printk("hashtable: module init success\n");

	return 0;
}

static void __exit hashtable_exit(void)
{
	unsigned int i;
	ht_data_t *data;
	struct hlist_node *tmp_hnode;

	// proc node clear
	proc_remove(proc_node_entry);

	// hash table clear
	for(i = 0; i < HASH_TABLE_SIZE; i++) {
		hlist_for_each_entry_safe(data, tmp_hnode, g_hash_table + i, hnode) {
			hlist_del_init(&(data->hnode));
			kfree(data);
			data = NULL;
		}
	}

	printk("hashtable: module exit success\n");

	return;
}

module_init(hashtable_init);
module_exit(hashtable_exit);

MODULE_AUTHOR("Steven Lee");
MODULE_DESCRIPTION("Hash Table");
MODULE_LICENSE("GPL");
