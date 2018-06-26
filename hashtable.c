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
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/slab.h>

#define HASH_TABLE_SIZE	(8)
#define HASH_KEY_MAX_LEN	(256)
#define HASH_VALUE_MAX_LEN	(512)
#define MAX_BUF_SIZE (HASH_KEY_MAX_LEN + HASH_VALUE_MAX_LEN + 16)

#define SYSCALL_FAKE_NUM	(223)

enum HASH_CMD {
	HASH_ADD,
	HASH_DEL,
	HASH_GET
};

typedef char* hash_key_t;
typedef char* hash_value_t;
typedef unsigned int hash_len_t;

typedef struct ht_data{
	hash_key_t key;
	hash_value_t value;
	hash_len_t ksize;
	hash_len_t vsize;
	struct hlist_node hnode;
}ht_data_t;

static struct hlist_head g_hash_table[HASH_TABLE_SIZE];
static rwlock_t g_hash_table_rwlock[HASH_TABLE_SIZE];

static unsigned long g_syscall_fake_addr;
static void *g_syscall_fake_func;
static unsigned long g_syscall_table_addr;
module_param(g_syscall_table_addr, ulong, 0);
MODULE_PARM_DESC(g_syscall_table_addr, "syscall table address");

static const char *proc_node_name = "hashtable";
static struct proc_dir_entry *proc_node_entry;

static char proc_msg[MAX_BUF_SIZE];

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
static bool ht_node_search(const hash_key_t key, const hash_len_t ksize, unsigned int *ht_bucket_index, ht_data_t **data)
{
	bool ret = false;
	ht_data_t *tmp_data;

	// get the hash bucket index
	unsigned int index = ht_hash_create(key);

	// read lock
	read_lock(&g_hash_table_rwlock[index]);
	hlist_for_each_entry(tmp_data, g_hash_table + index, hnode) {
		if(memcmp(key, (hash_key_t)(tmp_data->key), ksize) == 0
				&& ksize == tmp_data->ksize) {
			//printk("debug: query key: %s, store key: %s\n", key, tmp_data->key);
			ret = true;
			break;
		}
	}
	// read unlock
	read_unlock(&g_hash_table_rwlock[index]);

	*ht_bucket_index = index;
	*data = tmp_data;

	return ret;
}

static inline ht_data_t *ht_node_create(const hash_key_t key, const hash_len_t ksize, const hash_value_t value, const hash_len_t vsize)
{
	ht_data_t *data;

	data = (ht_data_t *) kmalloc(sizeof(ht_data_t), GFP_KERNEL);
	data->key = (hash_key_t) kmalloc(sizeof(hash_key_t) * ksize, GFP_KERNEL);
	data->value = (hash_value_t) kmalloc(sizeof(hash_value_t) * vsize, GFP_KERNEL);

	if(data == NULL || data->key == NULL || data->value == NULL) {
		printk("hashtable: kmalloc failed\n");
		return NULL;
	}

	memcpy(data->key, key, ksize);
	memcpy(data->value, value, vsize);
	data->ksize = ksize;
	data->vsize = vsize;

	INIT_HLIST_NODE(&(data->hnode));

	return data;
}

static inline void ht_node_remove(ht_data_t *data)
{
	if (!data) return;

	hlist_del_init(&(data->hnode));

	if(data->key) {
		kfree(data->key);
		data->key = NULL;
	}
	if(data->value) {
		kfree(data->value);
		data->value = NULL;
	}

	kfree(data);
	data = NULL;

	return;
}


void ht_data_add(const hash_key_t key, const hash_len_t ksize, const hash_value_t value, const hash_len_t vsize)
{
	unsigned int index;
	ht_data_t *data;

	// find if the node is exist
	if(ht_node_search(key, ksize, &index, &data)) {
		// the key is already exist, update it ?
		// write lock
		write_lock(&g_hash_table_rwlock[index]);
		ht_node_remove(data);
		// write unlock
		write_unlock(&g_hash_table_rwlock[index]);
	}

	// if not find exist node, copy as a new node
	data = ht_node_create(key, ksize, value, vsize);
	if (data == NULL) return;

	// write lock
	write_lock(&g_hash_table_rwlock[index]);
	// add the node to the hlist
	hlist_add_head(&(data->hnode), g_hash_table + index);
	// write unlock
	write_unlock(&g_hash_table_rwlock[index]);

	return;
}
EXPORT_SYMBOL(ht_data_add);

void ht_data_remove(const hash_key_t key, const hash_len_t ksize)
{
	unsigned int index;
	ht_data_t *data;

	if(!ht_node_search(key, ksize, &index, &data)) {
		return;
	}

	// write lock
	write_lock(&g_hash_table_rwlock[index]);
	// hash node del
	ht_node_remove(data);
	//write unlock
	write_unlock(&g_hash_table_rwlock[index]);

	return;
}
EXPORT_SYMBOL(ht_data_remove);


// query the value of the key
int ht_data_query(const hash_key_t key, const hash_len_t ksize, hash_value_t *value, hash_len_t *vsize) {
	unsigned int index;
	ht_data_t *data;

	if(!ht_node_search(key, ksize, &index, &data)) {
		return -1;
	}

	*value = data->value;
	*vsize = data->vsize;

	return 0;
}
EXPORT_SYMBOL(ht_data_query);

// page permission helper
static void page_addr_rw(unsigned long address)
{
	unsigned int level;
	pte_t *p = lookup_address(address, &level);
	if(p->pte & ~_PAGE_RW) {
		p->pte |= _PAGE_RW;
	}

	return;
}

static void page_addr_ro(unsigned long address)
{
	unsigned int level;
	pte_t *p = lookup_address(address, &level);
	p->pte &= ~_PAGE_RW;

	return;
}

asmlinkage long sys_hashtable(int cmd, const hash_key_t key, const hash_len_t ksize, hash_value_t *value, hash_len_t *vsize)
{
	int ret = 0;
	printk("hashtable: call the hashtable via syscall\n");

	switch(cmd) {
		case HASH_ADD:
			printk("hashtable: run add, key: %s, value: %s\n", key, *value);
			ht_data_add(key, ksize, *value, *vsize);
			break;
		case HASH_DEL:
			printk("hashtable: run del, key: %s\n", key);
			ht_data_remove(key, ksize);
			break;
		case HASH_GET:
			printk("hashtable: run get, key: %s\n", key);
			ret = ht_data_query(key, ksize, value, vsize);
			if (ret == 0) {
				printk("hashtable: query out the value: %s\n", *value);
			} else {
				printk("hashtable: not found the key: %s\n", key);
			}
			break;
		default:
			break;
	}

	return (long)ret;
}

static int sys_init_module(void)
{
	unsigned long *p;
	// get the syscall table address
	g_syscall_table_addr = kallsyms_lookup_name("sys_call_table");
	if (g_syscall_table_addr == 0) {
		printk("hashtable: not found the sys_call_table symbol\n");
		return -1;
	}

	// get fake address
	g_syscall_fake_addr = g_syscall_table_addr + sizeof(long) * SYSCALL_FAKE_NUM;

	// store the old func
	p = (unsigned long *)g_syscall_fake_addr;
	g_syscall_fake_func = (void *)(*p);

	// fake to own func
	page_addr_rw(g_syscall_fake_addr);
	*p = (unsigned long)sys_hashtable;
	page_addr_ro(g_syscall_fake_addr);

	return 0;
}

static int sys_cleanup_module(void)
{
	unsigned long *p;
	p = (unsigned long *)g_syscall_fake_addr;

	// revert fake addr
	page_addr_rw(g_syscall_fake_addr);
	*p = (unsigned long)g_syscall_fake_func;
	page_addr_ro(g_syscall_fake_addr);

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
			ht_data_add(key, strlen(key) + 1, value, strlen(value) + 1);
		}
	}
	// delete key
	else if (strncmp("del", msg, strlen("del")) == 0) {
		for(p = strsep(&s, delim); p != NULL; p = strsep(&s, delim)) {
			key = p;
			printk("hashtable: del key: %s\n", key);
			ht_data_remove(key, strlen(key) + 1);
		}
	}
	// query key
	else if (strncmp("get", msg, strlen("get")) == 0) {
		for(p = strsep(&s, delim); p != NULL; p = strsep(&s, delim)) {
			hash_value_t value;
			hash_len_t vsize;
			key = p;
			if(ht_data_query(key, strlen(key) + 1, &value, &vsize) == 0 ) {
				printk("hashtable: found the key: %s, value: %s\n", key, value);
			} else {
				printk("hashtable: not found the key: %s\n", key);
			}
		}
	}

	return len;
}

static struct file_operations proc_node_fops = {
	.owner = THIS_MODULE,
	.read = proc_node_read,
	.write = proc_node_write,
};

static int __init hashtable_init(void)
{
	unsigned int i;

	// hash table bucket init	
	for(i = 0; i < HASH_TABLE_SIZE; i++) {
		INIT_HLIST_HEAD(g_hash_table + i);
		rwlock_init(&g_hash_table_rwlock[i]);
	}

	// system call replace
	sys_init_module();

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

	// system call revert
	sys_cleanup_module();

	// hash table clear
	for(i = 0; i < HASH_TABLE_SIZE; i++) {
		// write lock
		write_lock(&g_hash_table_rwlock[i]);
		hlist_for_each_entry_safe(data, tmp_hnode, g_hash_table + i, hnode) {
			hlist_del_init(&(data->hnode));
			kfree(data);
			data = NULL;
		}
		// write unlock
		write_unlock(&g_hash_table_rwlock[i]);
	}

	printk("hashtable: module exit success\n");

	return;
}

module_init(hashtable_init);
module_exit(hashtable_exit);

MODULE_AUTHOR("Steven Lee");
MODULE_DESCRIPTION("Hash Table");
MODULE_LICENSE("GPL");
