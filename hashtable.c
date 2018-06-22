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

#include <linux/stddef.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>


#define HASH_TABLE_SIZE (8)

typedef char* hash_key_t;
typedef char* hash_value_t;

typedef struct ht_data{
	hash_key_t key;
	hash_value_t value;
	struct hlist_node hnode;
}ht_data_t;

struct hlist_head g_hash_table[HASH_TABLE_SIZE];

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
		if(strcmp(key, tmp_data->key) == 0) {
			break;
		}
	}

	*ht_bucket_index = index;
	*data = tmp_data;

	return tmp_data != NULL;
}

static void ht_data_add(ht_data_t *new_data)
{
	unsigned int index;
	ht_data_t *data;

	
	// find if the node is exist
	if(ht_search_by_key(new_data->key, &index, &data)) {
		// the key is already exist, update it ?
		data->value = new_data->value;
		return;
	}

	// if not find exist node, copy as a new node
	data = (ht_data_t *)kmalloc(sizeof(ht_data_t), GFP_KERNEL);
	if(data == NULL) {
		return;
	}

	memcpy(data, new_data, sizeof(ht_data_t));

	INIT_HLIST_NODE(&(data->hnode));

	// add the node to the hlist
	hlist_add_head(&(data->hnode), g_hash_table + index);  // index: table bucket index

	return;
}

static int ht_data_remove(const hash_key_t key)
{
	unsigned int index;
	ht_data_t *data;

	if(!ht_search_by_key(key, &index, &data)) {
		// do not find the key
		return -1;
	}

	hlist_del_init(&(data->hnode));

	kfree(data);

	return 0;
}


// query the value of the key
static int ht_data_query(const hash_key_t key, hash_value_t *value)
{
	unsigned int index;
	ht_data_t *data;

	if(!ht_search_by_key(key, &index, &data)) {
		// node not found
		return -1;
	}

	*value = data->value;

	return 0;
}

static int hashtable_init(void)
{
	unsigned int i;
	// hash table bucket init	
	for(i = 0; i < HASH_TABLE_SIZE; i++) {
		INIT_HLIST_HEAD(g_hash_table + i);
	}

	return 0;
}

static void hashtable_exit(void)
{
	unsigned int i;
	ht_data_t *data;
	struct hlist_node *tmp_hnode;

	// hash table clear
	for(i = 0; i < HASH_TABLE_SIZE; i++) {
		hlist_for_each_entry_safe(data, tmp_hnode, g_hash_table + i, hnode) {
			hlist_del_init(&(data->hnode));
			kfree(data);
		}
	}

	return;
}

module_init(hashtable_init);
module_exit(hashtable_exit);

MODULE_AUTHOR("Steven Lee");
MODULE_DESCRIPTION("Hash Table");
MODULE_LICENSE("GPL");
