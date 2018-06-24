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

extern void ht_data_add(const char*, const char*);
extern void ht_data_remove(const char*);
extern int ht_data_query(const char*, char**);

static int __init unit_init(void)
{
	char *p, *p1;
	char key[] = "key1";
	char value[] = "value1";

	p = (char *) kmalloc(sizeof(char), GFP_KERNEL);
	p1 = (char *) kmalloc(sizeof(char), GFP_KERNEL);
	if (p == NULL || p1 == NULL) {
		printk("debug: memory alloc failed\n");
		return -1;
	}

	// insert key - value
	ht_data_add(key, value);
	printk("debug: success to store the key: %s, value: %s\n", key, value);

	// query key
	if(ht_data_query(key, &p) == 0) {
		printk("debug: success to find the key: %s, value: %s\n", key, p);
	} else {
		printk("debug: failed to find the key: %s\n", key);
	}

	if (p) {
		kfree(p);
		p = NULL;
	}

	// remove key
	ht_data_remove(key);
	printk("debug: remove the key: %s, query again\n", key);

	// remove test query
	if(ht_data_query(key, &p1) == 0) {
		printk("debug: success to find the key: %s, value: %s\n", key, p1);
	} else {
		printk("debug: failed to find the key: %s\n", key);
	}

	if (p1) {
		kfree(p1);
		p1 = NULL;
	}

	return 0;
}

static void __exit unit_exit(void)
{
	printk("debug: hashtable unit test module exit\n");
	return;
}

module_init(unit_init);
module_exit(unit_exit);
MODULE_AUTHOR("Steven Lee");
MODULE_LICENSE("GPL");
