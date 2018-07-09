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
#include <linux/atomic.h>
#include <asm/atomic.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "hashtable.h"

#define HASH_TABLE_MIN_SIZE	(8)
#define HASH_TABLE_MAX_SIZE	(INT_MAX)
#define HASH_KEY_MAX_LEN	(256)
#define HASH_VALUE_MAX_LEN	(512)
#define MAX_BUF_SIZE (HASH_KEY_MAX_LEN + HASH_VALUE_MAX_LEN + 16)

#define SWAP(x, n, y) { n = x; x = y, y = n; }

#define HT_ERR(fmt, ...) \
    printk(KERN_ERR "hashtable - %s[%04u]: " fmt, __func__, __LINE__, ##__VA_ARGS__)

#define HT_INFO(fmt, ...) \
    printk(KERN_INFO "hashtable - %s[%04u]: " fmt, __func__, __LINE__, ##__VA_ARGS__)

#define HT_DEBUG(fmt, ...) \
    printk(KERN_DEBUG "hashtable - %s[%04u]: " fmt, __func__, __LINE__, ##__VA_ARGS__)

#define SYSCALL_FAKE_NUM	(223)

static hash_table_t ht;

static unsigned long g_syscall_fake_addr;
static void *g_syscall_fake_func;
static unsigned long g_syscall_table_addr;
module_param(g_syscall_table_addr, ulong, 0);
MODULE_PARM_DESC(g_syscall_table_addr, "syscall table address");

static const char *proc_node_name = "hashtable";
static struct proc_dir_entry *proc_node_entry;


/****************************************
 * ---							---
 * ---		DATA FUNCTIONS		---
 * ---							---
 * note: all function thread safety.
 ***************************************/

/**
 * BKDRHash hash create
 */
static unsigned int ht_hash_create(const char *key)
{
	unsigned int seed = 131;
	register unsigned int hash = 0;

	while(*key) {
		hash = hash * seed + (*key++);
	}

	return (hash & 0x7FFFFFFF);
}

/**
 * create a base key-value pair
 */
static inline ht_data_t *ht_node_create(const hash_key_t key, const hash_len_t ksize, const hash_value_t value, const hash_len_t vsize)
{
	ht_data_t *data;

	data = (ht_data_t *) kmalloc(sizeof(ht_data_t), GFP_KERNEL);
	if (!data)
		return NULL;

	data->key = (hash_key_t) kmalloc(sizeof(hash_key_t) * ksize, GFP_KERNEL);
	if (!data->key) {
		kfree(data);
		data = NULL;
		return NULL;
	}
	data->value = (hash_value_t) kmalloc(sizeof(hash_value_t) * vsize, GFP_KERNEL);
	if (!data->value) {
		kfree(data->key);
		data->key = NULL;
		kfree(data);
		data = NULL;
		return NULL;
	}

	memcpy(data->key, key, ksize);
	memcpy(data->value, value, vsize);
	data->ksize = ksize;
	data->vsize = vsize;

	INIT_HLIST_NODE(&(data->hnode));

	return data;
}

/**
 * destroy a key-pair node
 */
static inline void ht_node_destroy(ht_data_t *data)
{
	if (!data)
		return;

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

	return;
}

/**
 * hashtable entry create
 */
static inline hash_entry_t *ht_entry_create(int size)
{
	int i;
	hash_entry_t *entry;
	
	entry = (hash_entry_t *) kmalloc(sizeof(hash_entry_t), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->size = size;

	entry->bucket = (struct hlist_head *) vmalloc(sizeof(struct hlist_head) * size);
	if (!entry->bucket) {
		kfree(entry);
		entry = NULL;
		return NULL;
	}
	entry->rwlock = (rwlock_t *) vmalloc(sizeof(rwlock_t) * size);
	if (!entry->rwlock) {
		vfree(entry->bucket);
		entry->bucket = NULL;
		kfree(entry);
		entry = NULL;
		return NULL;
	}
	// sub init
	for(i = 0; i < size; i++) {
		INIT_HLIST_HEAD(entry->bucket + i);
		rwlock_init(entry->rwlock + i);
	}

	return entry;
}

/**
 * destroy the entry, lock out layer
 */
static void ht_entry_destroy(hash_entry_t *entry)
{
	int i;
	ht_data_t *pos;
	struct hlist_node *n;
	
	if (!entry)
		return;

	for(i = 0; i < entry->size; i++) {
		// write lock
		write_lock(entry->rwlock + i);

		hlist_for_each_entry_safe(pos, n, entry->bucket + i, hnode) {
			ht_node_destroy(pos);
		};
		// write unlock
		write_unlock(entry->rwlock + i);
	}

	// memory free
	vfree(entry->rwlock);
	entry->rwlock = NULL;
	vfree(entry->bucket);
	entry->bucket = NULL;

	kfree(entry);

	return;
}

/**
 * hashtable load factor count
 */
static inline unsigned int ht_table_load_get(void)
{
	unsigned int load;
	// read lock
	read_lock(&ht.rwlock);
	load = ht.members * 100 / ht.major->size;
	// write unlock
	read_unlock(&ht.rwlock);

	return load;
}

/**
 * hashtable members count
 */
static inline unsigned int ht_table_members_get(void)
{
	unsigned int members;
	// read lock
	read_lock(&ht.rwlock);
	members = ht.members;
	// read unlock
	read_unlock(&ht.rwlock);
	
	return members;
}

/**
 * hashtable member increse
 */
static inline void ht_table_members_inc(void)
{
	// write lock
	write_lock(&ht.rwlock);
	ht.members = ht.members + 1;
	// write unlock
	write_unlock(&ht.rwlock);
	
	return;
}

/**
 * hashtable member decrese
 */
static inline void ht_table_members_dec(void)
{
	// write lock
	write_lock(&ht.rwlock);
	ht.members = ht.members - 1;
	// write unlock
	write_unlock(&ht.rwlock);
	
	return;
}

/****************************************
 * ---							---
 * ---		LOGIC FUNCTIONS		---
 * ---							---
 ***************************************/

/**
 * search node by key
 */
static int ht_node_search(const hash_key_t key, const hash_len_t ksize, unsigned int *ht_bucket_index, ht_data_t **data)
{
	int ret = HASH_NOT_FOUND;
	ht_data_t *pos;
	unsigned int index;

	// major entry query
	index = ht_hash_create(key) % ht.major->size;


	// read lock
	read_lock(&ht.rwlock);
	read_lock(ht.major->rwlock + index);

	hlist_for_each_entry(pos, ht.major->bucket + index, hnode) {
		if(memcmp(key, (hash_key_t)(pos->key), ksize) == 0
				&& ksize == pos->ksize) {
			//HT_DEBUG("major table: query key: %s, found key: %s, value: %s\n", key, pos->key, pos->value);
			ret = HASH_IN_MAJOR;
			break;
		}
	}
	// read unlock
	read_unlock(ht.major->rwlock + index);
	read_unlock(&ht.rwlock);

	/*
	// minor entry query
	if (ret == HASH_NOT_FOUND && ht.minor != NULL
			&& ht_table_isrehashed(&rehash_idx) == false) {
		index = ht_hash_create(key) % ht.minor->size;

		if (index > rehash_idx) {
			// read lock
			read_lock(ht.minor->rwlock + index);

			hlist_for_each_entry(pos, ht.minor->bucket + index, hnode) {
				if (memcmp(key, (hash_key_t)(pos->key), ksize) == 0
						&& ksize == pos->ksize) {
					//HT_DEBUG("minor table: query key: %s, found key: %s, value: %s\n", key, pos->key, pos->value);
					ret = HASH_IN_MINOR;
					break;
				}
			}
			// read unlock
			read_unlock(ht.minor->rwlock + index);
		}
	}
	*/

	*ht_bucket_index = index;
	*data = pos;

	return ret;
}

/**
 * transfer a node to major entry
 */
static void ht_node_transfer(const hash_key_t key, const hash_len_t ksize, const hash_value_t value, const hash_len_t vsize)
{
	unsigned int index;
	ht_data_t *data;

	index = ht_hash_create(key) % ht.major->size;

	// minor to major, just add
	data = ht_node_create(key, ksize, value, vsize);
	if (data == NULL)
		return;

	// write lock
	write_lock(ht.major->rwlock + index);
	// add the node to the hlist
	hlist_add_head(&(data->hnode), ht.major->bucket + index);
	// write unlock
	write_unlock(ht.major->rwlock + index);

	// major members increase
	ht_table_members_inc();

	return;
}

/**
 * hashtable rehash
 */
static void ht_table_rehash(void)
{
	ht_data_t *pos;
	struct hlist_node *n;
	unsigned int index;

	//HT_INFO("hashtable rehash start\n");

	for(index = 0; index < ht.minor->size; index++) {	
		// wrie lock
		write_lock(ht.minor->rwlock + index);

		hlist_for_each_entry_safe(pos, n, ht.minor->bucket + index, hnode) {
			ht_node_transfer(pos->key, pos->ksize, pos->value, pos->vsize);
			ht_node_destroy(pos);
			ht_table_members_dec();
		}
		// write unlock
		write_unlock(ht.minor->rwlock + index);
	}

	ht_entry_destroy(ht.minor);
	ht.minor = NULL;

	//HT_INFO("hashtable rehash complete\n");

	return;
}

/**
 * hash table resize
 */
static void ht_table_resize(const unsigned int size)
{
	hash_entry_t tmp;

	//HT_INFO("resize table, size to: %d\n", size);

	// create a new minor entry
	ht.minor = ht_entry_create(size);
	if (!ht.minor)
		return;
	
	// write lock
	write_lock(&ht.rwlock);

	// swap the major and minor
	SWAP(*ht.major, tmp, *ht.minor);

	// write unlock
	write_unlock(&ht.rwlock);

	// rehash table
	ht_table_rehash();

	//HT_INFO("hashtable resize complete\n");

	return;
}


/**
 * hash table kv data add
 */
void ht_data_add(const hash_key_t key, const hash_len_t ksize, const hash_value_t value, const hash_len_t vsize)
{
	ht_data_t *pos;
	unsigned int index;
	unsigned int load;

	// rehash lock
	mutex_lock(&ht.mutex);
	
	/* rehash operations */
	load = ht_table_load_get();
	
	//HT_DEBUG("add key: %s, value: %s, table size: %d, members: %d, load: %d\n", key, value, ht.major->size, ht_table_members_get(), load);

	if (load >= 90 && ht.major->size < HASH_TABLE_MAX_SIZE) {
		ht_table_resize(ht.major->size * 2);
	}
	// rehash unlock
	mutex_unlock(&ht.mutex);

	if (ht_node_search(key, ksize, &index, &pos) == HASH_IN_MAJOR) {
		ht_table_members_dec();
		// write lock
		write_lock(ht.major->rwlock + index);
		ht_node_destroy(pos);
		// write unlock
		write_unlock(ht.major->rwlock + index);
	}
	/*
	else if (ret == HASH_IN_MINOR) {
		// write lock
		write_lock(ht.minor->rwlock + index);
		ht_node_destroy(pos);
		// write unlock
		write_unlock(ht.minor->rwlock + index);
	}
	*/

	ht_node_transfer(key, ksize, value, vsize); // members will increase

	return;
}
EXPORT_SYMBOL(ht_data_add);

/**
 * ht_data_remove - remove the key - value
 */
void ht_data_remove(const hash_key_t key, const hash_len_t ksize)
{
	ht_data_t *pos;
	unsigned int index;
	unsigned int load;

	// rehash lock
	mutex_lock(&ht.mutex);
	
	/* rehash operations */
	load = ht_table_load_get();

	if (load <= 10 && ht.major->size > HASH_TABLE_MIN_SIZE) {
		ht_table_resize(ht.major->size / 2);
	}

	// rehash unlock
	mutex_unlock(&ht.mutex);

	//HT_DEBUG("del key: %s, table size: %d, members: %d, load: %d\n", key, ht.major->size, ht_table_members_get(), load);

	if (ht_node_search(key, ksize, &index, &pos) == HASH_NOT_FOUND) {
		return;
	}

	// write lock
	write_lock(ht.major->rwlock + index);
	
	// hash node del
	ht_node_destroy(pos);
	//write unlock
	write_unlock(ht.major->rwlock + index);

	// members update
	ht_table_members_dec();

	return;
}
EXPORT_SYMBOL(ht_data_remove);

/**
 * ht_data_query - query data by key and size
 */
int ht_data_query(const hash_key_t key, const hash_len_t ksize, hash_value_t *value, hash_len_t *vsize) {
	unsigned int index;
	ht_data_t *data;

	if(ht_node_search(key, ksize, &index, &data) == HASH_NOT_FOUND) {
		return -1;
	}

	//HT_DEBUG("query key: %s, get key: %s, value: %s\n", key, data->key, data->value);

	*value = data->value;
	*vsize = data->vsize;

	return 0;
}
EXPORT_SYMBOL(ht_data_query);


/****************************************
 * ---								---
 * ---		PLATFORM FUNCTIONS		---
 * ---								---
 ***************************************/

/**
 * set page address rw
 */
static void page_addr_rw(unsigned long address)
{
	unsigned int level;
	pte_t *p = lookup_address(address, &level);
	if(p->pte & ~_PAGE_RW) {
		p->pte |= _PAGE_RW;
	}

	return;
}

/**
 * set page address ro
 */
static void page_addr_ro(unsigned long address)
{
	unsigned int level;
	pte_t *p = lookup_address(address, &level);
	p->pte &= ~_PAGE_RW;

	return;
}

/**
 * syscall hashtable interface
 */
asmlinkage long sys_hashtable(int cmd, const hash_key_t key, const hash_len_t ksize, hash_value_t *value, hash_len_t *vsize)
{
	int ret = 0;
	HT_INFO("hashtable: call the hashtable via syscall\n");

	switch(cmd) {
		case HASH_ADD:
			HT_INFO("syscall add, key: %s, value: %s\n", key, *value);
			ht_data_add(key, ksize, *value, *vsize);
			break;
		case HASH_DEL:
			HT_INFO("syscall del, key: %s\n", key);
			ht_data_remove(key, ksize);
			break;
		case HASH_GET:
			HT_INFO("syscall get, key: %s\n", key);
			ret = ht_data_query(key, ksize, value, vsize);
			if (ret == 0) {
				HT_INFO("syscall query out the value: %s\n", *value);
			} else {
				HT_INFO("syscall not found the key: %s\n", key);
			}
			break;
		default:
			break;
	}

	return (long)ret;
}

/**
 * syscall module init
 */
static int sys_hashtable_init(void)
{
	unsigned long *p;
	// get the syscall table address
	g_syscall_table_addr = kallsyms_lookup_name("sys_call_table");
	if (g_syscall_table_addr == 0) {
		HT_ERR("not found the sys_call_table symbol\n");
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

/**
 * syscall module exit
 */
static int sys_hashtable_cleanup(void)
{
	unsigned long *p;
	p = (unsigned long *)g_syscall_fake_addr;

	// revert fake addr
	page_addr_rw(g_syscall_fake_addr);
	*p = (unsigned long)g_syscall_fake_func;
	page_addr_ro(g_syscall_fake_addr);

	return 0;
}

/**
 * procfs read callback
 */
static ssize_t proc_node_read(struct file *file, char __user *buffer, size_t count, loff_t *pos)
{
	int i;
	ht_data_t *node;
	char msg[MAX_BUF_SIZE] = { 0 };

	sprintf(msg, "Please see all store members by `dmesg`\n");

	for(i = 0; i < ht.major->size; i++) {
		read_lock(ht.major->rwlock + i);

		hlist_for_each_entry(node, ht.major->bucket + i, hnode) {
			HT_INFO("bucket: %d, key: %s, value: %s\n", i, node->key, node->value);
		}

		read_unlock(ht.major->rwlock + i);
	}

	return simple_read_from_buffer(buffer, count, pos, msg, strlen(msg));;
}

/**
 * procfs write callback
 */
static ssize_t proc_node_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
	char msg[MAX_BUF_SIZE] = { 0 };
	char args[MAX_BUF_SIZE] = { 0 };
	ssize_t len;
	const char *delim = " ";
	hash_key_t key;
	hash_value_t value;
	char *s, *p = NULL;

	len = simple_write_to_buffer(msg, sizeof(msg), pos, buffer, count);
	memcpy(args, msg + 4, count - 5); // no need '\n'
	s = args;

	// add key-value
	if(strncmp(msg, "add", strlen("add")) == 0) {
		for(p = strsep(&s, delim); p != NULL; p = strsep(&s, delim)) {
			key = p;
			value = strsep(&s, delim);
			HT_INFO("procfs add key: %s, value: %s\n", key, value);
			ht_data_add(key, strlen(key) + 1, value, strlen(value) + 1);
		}
	}
	// delete key
	else if (strncmp("del", msg, strlen("del")) == 0) {
		for(p = strsep(&s, delim); p != NULL; p = strsep(&s, delim)) {
			key = p;
			HT_INFO("procfs del key: %s\n", key);
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
				HT_INFO("procfs found the key: %s, value: %s\n", key, value);
			} else {
				HT_INFO("procfs not found the key: %s\n", key);
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
	// lock init
	ht.members = 0;
	rwlock_init(&ht.rwlock);
	mutex_init(&ht.mutex);

	// create a major entry
	ht.major = ht_entry_create(HASH_TABLE_MIN_SIZE);
	if (!ht.major) {
		HT_ERR("failed to create hash entry\n");
		return -1;
	}

	// system call replace
	sys_hashtable_init();

	// procfs node create
	if((proc_node_entry = proc_create(proc_node_name, S_IFREG | S_IRUGO | S_IWUGO, NULL, &proc_node_fops)) == NULL) {
		HT_ERR("failed to create proc fs node: %s\n", proc_node_name);
		return -2;
	}
	
	HT_INFO("hashtable: module init success\n");

	return 0;
}

static void __exit hashtable_exit(void)
{
	// proc node clear
	proc_remove(proc_node_entry);

	// system call revert
	sys_hashtable_cleanup();

	// major entry cleanup
	if (ht.major) {
		ht_entry_destroy(ht.major);
		ht.major = NULL;
	}
	// minor entry cleanup
	if (ht.minor) {
		ht_entry_destroy(ht.minor);
		ht.minor = NULL;
	}

	HT_INFO("hashtable: module exit success\n");

	return;
}

module_init(hashtable_init);
module_exit(hashtable_exit);

MODULE_AUTHOR("Steven Lee");
MODULE_DESCRIPTION("Hash Table");
MODULE_LICENSE("GPL");
