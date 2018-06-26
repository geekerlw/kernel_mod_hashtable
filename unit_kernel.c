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

extern void ht_data_add(const char*, const unsigned int, const char*, unsigned int);
extern void ht_data_remove(const char*, const unsigned int);
extern int ht_data_query(const char*, const unsigned int, char**, unsigned int*);

static int __init unit_init(void)
{
	unsigned int vsize;
	unsigned long store = 0;
	char key[] = "key1";
	char value[] = "value1";
	char *p = (char *)store;
	char *q = (char *)store;

	printk("unit: hashtable unit test module init\n");
	// insert key - value
	ht_data_add(key, strlen(key) + 1, value, strlen(value) + 1);
	printk("unit: success to store the key: %s, value: %s\n", key, value);

	// query key
	if(ht_data_query(key, strlen(key) + 1, &p, &vsize) == 0) {
		printk("unit: success to find the key: %s, value: %s\n", key, p);
	} else {
		printk("unit: failed to find the key: %s\n", key);
	}

	// remove key
	ht_data_remove(key, strlen(key) + 1);
	printk("unit: remove the key: %s, query again\n", key);

	// remove test query
	if(ht_data_query(key, strlen(key) + 1, &q, &vsize) == 0) {
		printk("unit: success to find the key: %s, value: %s\n", key, q);
	} else {
		printk("unit: failed to find the key: %s\n", key);
	}

	return 0;
}

static void __exit unit_exit(void)
{
	printk("unit: hashtable unit test module exit\n");
	return;
}

module_init(unit_init);
module_exit(unit_exit);
MODULE_AUTHOR("Steven Lee");
MODULE_LICENSE("GPL");
