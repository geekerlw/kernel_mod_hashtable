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

#ifndef __HASHTABLE_H__
#define __HASHTABLE_H__

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

typedef struct ht_data {
	hash_key_t key;
	hash_value_t value;
	hash_len_t ksize;
	hash_len_t vsize;
	struct hlist_node hnode;
}ht_data_t;

typedef struct hash_entry {
	struct hlist_head *bucket; // hashtable bucket
	rwlock_t *rwlock; // each hlist a lock
	unsigned int size; // bucket size
}hash_entry_t;

typedef struct hash_table {
	hash_entry_t *major; // major entry
	hash_entry_t *minor; // minor entry, a tmp
	unsigned int members; // store count
	struct mutex mutex; // struct change lock
	rwlock_t rwlock; // members lock
}hash_table_t;

#endif
