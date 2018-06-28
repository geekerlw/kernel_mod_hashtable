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
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/slab.h>

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

enum HASH_CMD {
	HASH_ADD,
	HASH_DEL,
	HASH_GET
};

enum HASH_NODE_POS {
	HASH_NOT_FOUND,
	HASH_IN_MAJOR,
	HASH_IN_MINOR
};

typedef char* hash_key_t;
typedef char* hash_value_t;
typedef unsigned int hash_len_t;

typedef struct hash_entry {
	struct hlist_head *bucket;
	rwlock_t *rwlock;
	unsigned int size;
}hash_entry_t;

typedef struct hash_table {
	hash_entry_t *major;
	hash_entry_t *minor;
	unsigned int rehash_idx;
	bool rehashed;
	atomic_t members;
	struct mutex mutex;
}hash_table_t;

typedef struct ht_data {
	hash_key_t key;
	hash_value_t value;
	hash_len_t ksize;
	hash_len_t vsize;
	struct hlist_node hnode;
}ht_data_t;	

static struct hash_table ht = {
	.rehash_idx = 0,
	.rehashed = true,
	.members = ATOMIC_INIT(0),
};
static DEFINE_MUTEX(g_rehash_mutex); 

static unsigned long g_syscall_fake_addr;
static void *g_syscall_fake_func;
static unsigned long g_syscall_table_addr;

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

	entry->bucket = (struct hlist_head*) kmalloc(sizeof(struct hlist_head) * size, GFP_KERNEL);
	if (!entry->bucket) {
		kfree(entry);
		entry = NULL;
		return NULL;
	}
	entry->rwlock = (rwlock_t *) kmalloc(sizeof(rwlock_t *) * size, GFP_KERNEL);
	if (!entry->rwlock) {
		kfree(entry->bucket);
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
			pos = NULL;
		};
		// write unlock
		write_unlock(entry->rwlock + i);
	}

	// memory free
	kfree(entry->rwlock);
	entry->rwlock = NULL;
	kfree(entry->bucket);
	entry->bucket = NULL;

	kfree(entry);

	return;
}

/**
 *  whether minor hash table is rehashed complete
 */
static inline bool ht_table_isrehashed(unsigned int *rehash_idx)
{
	bool ret;
	// mutex lock
	mutex_lock(&ht.mutex);
	ret = ht.rehashed;
	*rehash_idx = ht.rehash_idx;
	// mutex unlock
	mutex_unlock(&ht.mutex);

	return ret;
}

/**
 * updata minor table rehash state
 */
static inline void ht_table_set_rehashed(bool rehashed, const unsigned int rehash_idx)
{
	// mutex lock
	mutex_lock(&ht.mutex);
	ht.rehashed = rehashed;
	ht.rehash_idx = rehash_idx;
	// mutex unlock
	mutex_unlock(&ht.mutex);

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
	unsigned int index, rehash_idx;
	ht_data_t *pos;

	// major entry query
	index = ht_hash_create(key) % ht.major->size;

	// read lock
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

	// minor entry query
	if (ret == HASH_NOT_FOUND && ht_table_isrehashed(&rehash_idx) == false) {
		// create minor hash
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

	*ht_bucket_index = index;
	*data = pos;

	return ret;
}

/**
 * transfer a node to major entry
 */
static void ht_node_transfer(ht_data_t *pos)
{
	unsigned int index;
	ht_data_t *data;

	if (!pos)
		return;

	// minor to major, just add
	data = ht_node_create(pos->key, pos->ksize, pos->value, pos->vsize);
	if (data == NULL)
		return;

	index = ht_hash_create(pos->key) % ht.major->size;

	// write lock
	write_lock(ht.major->rwlock + index);
	// add the node to the hlist
	hlist_add_head(&(data->hnode), ht.major->bucket + index);
	// write unlock
	write_unlock(ht.major->rwlock + index);

	return;
}

/**
 * hash table resize
 */
static void ht_table_resize(const unsigned int size)
{
	hash_entry_t tmp;

	// create a new minor entry
	ht.minor = ht_entry_create(size);
	if (!ht.minor)
		return;
	
	// mutex lock
	mutex_lock(&ht.mutex);
	// swap the major and minor
	SWAP(*ht.major, tmp, *ht.minor);
	// mutex unlock
	mutex_unlock(&ht.mutex);

	// rehash start
	ht_table_set_rehashed(false, 0);

	return;
}

/**
 * hashtable rehash by step
 */
static void ht_table_rehash(void)
{
	ht_data_t *pos;
	struct hlist_node *n;
	unsigned int i, index, rehash_idx;
	unsigned int load, size;
	bool rehashed;

	size = ht.major->size;
	load = atomic_read(&ht.members) * 100 / ht.major->size;
	rehashed = ht_table_isrehashed(&rehash_idx);

	HT_DEBUG("rehash in, size: %d, members: %d, load: %d, rehashed: %d, idx: %d\n", size, atomic_read(&ht.members), load, (int)rehashed, rehash_idx);
	
	if (rehashed) {
		// load factor judge, swap the major and minor address
		if (load >= 90 && size < HASH_TABLE_MAX_SIZE) {
			printk("debug: increase size\n");
			ht_table_resize(size * 2);
		} else if (load <= 10  && size > HASH_TABLE_MIN_SIZE) {
			printk("debug: decrese size\n");
			ht_table_resize(size / 2);
		}
	} else {
		index = rehash_idx;
		// rehash by step
		for(i = 0; i < HASH_TABLE_MIN_SIZE && index < ht.minor->size; i++) {
			// read lock
			read_lock(ht.minor->rwlock + index);
	
			hlist_for_each_entry_safe(pos, n, ht.minor->bucket + index, hnode) {
				ht_node_transfer(pos);
			}
			// write unlock
			read_unlock(ht.major->rwlock + index);
			index++;
		}

		if (index == ht.minor->size) {
			// rehash complete
			ht_table_set_rehashed(true, 0);
			ht_entry_destroy(ht.minor);
			ht.minor = NULL;
		} else {
			ht_table_set_rehashed(false, index - 1);
		}
	}

	return;
}

/**
 * hash table kv data add
 */
void ht_data_add(const hash_key_t key, const hash_len_t ksize, const hash_value_t value, const hash_len_t vsize)
{
	ht_data_t *data, *pos;
	unsigned int index;
	int ret;
	
	/* rehash operations */
//	mutex_lock(&g_rehash_mutex);
	ht_table_rehash();
//	mutex_unlock(&g_rehash_mutex);

	/* hash store operation */
	data = ht_node_create(key, ksize, value, vsize);
	if (data == NULL) return;

	ret = ht_node_search(key, ksize, &index, &pos);

	if (ret == HASH_IN_MAJOR) {
		// write lock
		write_lock(ht.major->rwlock + index);
		ht_node_destroy(pos);
		pos = NULL;
		// write unlock
		write_unlock(ht.major->rwlock + index);
	} else if (ret == HASH_IN_MINOR) {
		// write lock
		write_lock(ht.minor->rwlock + index);
		ht_node_destroy(pos);
		pos = NULL;
		// write unlock
		write_unlock(ht.minor->rwlock + index);
	} else {
		// not found, member increase
		atomic_inc(&ht.members);
	}

	ht_node_transfer(data);

	return;
}
EXPORT_SYMBOL(ht_data_add);

/**
 * ht_data_remove - remove the key - value
 */
void ht_data_remove(const hash_key_t key, const hash_len_t ksize)
{
	unsigned int index;
	ht_data_t *pos;
	int ret;

	/* rehash operations */
//	mutex_lock(&g_rehash_mutex);
	ht_table_rehash();
//	mutex_unlock(&g_rehash_mutex);

	ret = ht_node_search(key, ksize, &index, &pos);
	if (ret == HASH_NOT_FOUND) {
		return;
	}

	// write lock
	write_lock(ht.major->rwlock + index);
	
	// hash node del
	ht_node_destroy(pos);
	pos = NULL;
	//write unlock
	write_unlock(ht.major->rwlock + index);

	// members update
	atomic_dec(&ht.members);

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
	printk("hashtable: call the hashtable via syscall\n");

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
static int sys_init_module(void)
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

/**
 * procfs read callback
 */
static ssize_t proc_node_read(struct file *file, char __user *buffer, size_t count, loff_t *pos)
{
	
	return 0;
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
	// mutex init
	mutex_init(&ht.mutex);

	// create a major entry
	ht.major = ht_entry_create(HASH_TABLE_MIN_SIZE);
	if (!ht.major) {
		HT_ERR("failed to create hash entry\n");
		return -1;
	}

	// system call replace
	sys_init_module();

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
	sys_cleanup_module();

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
