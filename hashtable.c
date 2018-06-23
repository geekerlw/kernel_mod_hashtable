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
		printk("debug: kmalloc failed\n");
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
		// do not find the key
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
		// node not found
		return -1;
	}

	*value = data->value;

	return 0;
}
EXPORT_SYMBOL(ht_data_query);

/*
static void hashtable_unit_test(void)
{
	char key[] = "key1";
	char value[] = "value1";

	char *p = (char *) kmalloc(sizeof(char), GFP_KERNEL);
	char *p1 = (char *) kmalloc(sizeof(char), GFP_KERNEL);

	// insert test
	ht_data_add(key, value);
	printk("debug: add the key: %s, value: %s\n", key, value);

	// query test
	ht_data_query(key, &p);
	printk("debug: query out the data: %s\n", p);
	kfree(p);

	// remove test
	if(ht_data_remove(key) == 0) {
		printk("debug: remove the key: %s\n", key);
		// query again
		if(ht_data_query(key, &p1) == 0) {
			printk("debug: query out the key: %s, value: %s\n", key, p1);
		} else {
			printk("debug: query failed, not found\n");
		}
	} else {
		printk("debug: remove the key failed, key: %s\n", key);
	}
	kfree(p1);	

	return;
}
*/

static int __init hashtable_init(void)
{
	unsigned int i;

	// hash table bucket init	
	for(i = 0; i < HASH_TABLE_SIZE; i++) {
		INIT_HLIST_HEAD(g_hash_table + i);
	}

	//hashtable_unit_test();
	
	printk("hashtable: module init success\n");

	return 0;
}

static void __exit hashtable_exit(void)
{
	unsigned int i;
	ht_data_t *data;
	struct hlist_node *tmp_hnode;

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
