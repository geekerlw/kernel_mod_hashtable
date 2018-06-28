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
#include <linux/kthread.h>
#include <linux/unistd.h>
#include <linux/time.h>
#include <linux/atomic.h>
#include <asm/atomic.h>

typedef struct bench_func {
	int (*threadfn)(void *data);
	void *data;
	const char *namefmt;
}bench_func_t;

#define TIME_NANOSECOND (1000 * 1000 * 1000)
#define MAX_INDEX_SIZE	(1 * 100)
#define MAX_THREAD_SIZE	(1)
#define MAX_KV_SIZE		(16)

extern void ht_data_add(const char *key, const unsigned int, const char *value, unsigned int);
extern void ht_data_remove(const char *key, const unsigned int);
extern void ht_data_query(const char *key, const unsigned int, char **value, unsigned int*);

static struct task_struct *task_benchmark;

static atomic_t atomic_index = ATOMIC_INIT(0);

// pair: key<x> -- value<x>
// eg. key23 -- value23
static inline void hash_kv_constructor(char *key, char *value)
{
	register int index;
	index = atomic_inc_return(&atomic_index);
	sprintf(key, "key%d", index);
	sprintf(value, "value%d", index);
	
	return;
}

static int thread_func_add(void *data)
{
	char key[MAX_KV_SIZE] = { 0 };
	char value[MAX_KV_SIZE]= { 0 };

	while(!kthread_should_stop()) {
		if(atomic_read(&atomic_index) < MAX_INDEX_SIZE) {
			hash_kv_constructor(key, value);
			ht_data_add(key, strlen(key) + 1, value, strlen(value) + 1);
			//printk("benchmark: add: key: %s, value: %s\n", key, value);
		}
	}

	return 0;
}

static int thread_func_remove(void *data)
{
	char key[MAX_KV_SIZE] = { 0 };
	char value[MAX_KV_SIZE] = { 0 };

	while(!kthread_should_stop()) {
		if(atomic_read(&atomic_index) < MAX_INDEX_SIZE) {
			hash_kv_constructor(key, value);
			ht_data_remove(key, strlen(key) + 1);
			//printk("benchmark: remove: key: %s, value: %s\n", key, value);
		}
	}

	return 0;
}

static int thread_func_query(void *data)
{
	char key[MAX_KV_SIZE] = { 0 };
	char value[MAX_KV_SIZE] = { 0 };
	unsigned int vsize = 0;
	unsigned long store = 0;
	char *p = (char *)store;

	while(!kthread_should_stop()) {
		if(atomic_read(&atomic_index) < MAX_INDEX_SIZE) {
			hash_kv_constructor(key, value);
			ht_data_query(key, strlen(key) + 1, &p, &vsize);
			//printk("benchmark: query: key: %s, value: %s\n", key, p);
		}
	}

	return 0;
}


static void benchmark_run(bench_func_t *pinfo)
{
	struct timespec start, end;
	struct task_struct *task[MAX_THREAD_SIZE];
	unsigned long long duration = 0;
	int i;
	
	// start benchmark
	start = current_kernel_time();

	for(i = 0; i < MAX_THREAD_SIZE; i++) {
		task[i] =  kthread_run(pinfo->threadfn, pinfo->data, pinfo->namefmt);
		//printk("benchmark: %s mission thread create, thread id: %d\n", pinfo->namefmt, i);
	}

	while(atomic_read(&atomic_index) < MAX_INDEX_SIZE) {
		schedule();
	}

	for(i = 0; i < MAX_THREAD_SIZE; i++) {
		if(!IS_ERR(task[i])) {
			kthread_stop(task[i]);
			//printk("benchmark: %s mission thread stop, thread id: %d\n", pinfo->namefmt, i);
		}
	}
	// end benchmark
	end = current_kernel_time();

	// result
	duration = (unsigned long long)(end.tv_sec - start.tv_sec) * TIME_NANOSECOND + (end.tv_nsec - start.tv_nsec);
	printk("benchmark: mission: %s, meta bench: %d, thread num: %d, start_time: %ld s, end_time: %ld s, duration: %lld ns, avg: %lld ns\n",
			pinfo->namefmt, atomic_read(&atomic_index), MAX_THREAD_SIZE, start.tv_sec, end.tv_sec, duration, duration / MAX_INDEX_SIZE);

	return;
}

static int benchmark_thread(void *data)
{
	bench_func_t info;
	info.data = NULL;

	// add test
	info.threadfn = thread_func_add;
	info.namefmt = "hash add";
	benchmark_run(&info);

	// reset index
	atomic_set(&atomic_index, 0);

	// query test
	info.threadfn = thread_func_query;
	info.namefmt = "hash get";
	benchmark_run(&info);

	// reset index
	atomic_set(&atomic_index, 0);

	// remove test
	info.threadfn = thread_func_remove;
	info.namefmt = "hash del";
	benchmark_run(&info);	

	while(!kthread_should_stop()) {
		schedule();
	}	

	printk("benchmark: thread benchmark all exit\n");

	return 0;
}

static int __init benchmark_init(void)
{
	printk("benchmark: module init\n");

	task_benchmark = kthread_run(benchmark_thread, NULL, "benchmark all");

	return 0;
}

static void __exit benchmark_exit(void)
{

	atomic_set(&atomic_index, MAX_INDEX_SIZE);

	if (!IS_ERR(task_benchmark)) {
		kthread_stop(task_benchmark);
	}

	printk("benchmark: module exit\n");

	return;
}

module_init(benchmark_init);
module_exit(benchmark_exit);
MODULE_AUTHOR("Steven Lee");
MODULE_LICENSE("GPL");
