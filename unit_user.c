#define _GNU_SOURCE
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <sys/syscall.h>

enum HASH_CMD {
	HASH_ADD,
	HASH_DEL,
	HASH_GET
};

int main(void)
{
	const char *key = "testkey1";
	const char *value = "testvalue1";
	int ret = 0;
	char *buf;

	//ret = syscall(__NR_mkdir, "somesjflsjjjjj", 2);
	ret = syscall(223, HASH_ADD, "key1", "value1");

	/*
	// add test
	ret = syscall(223, HASH_ADD, "key1", "value1");
	printf("add key: %s, value: %s\n", key, value);

	sleep(1);

	// get test
	ret = syscall(223, HASH_GET, "key1", &buf);
	printf("get key: %s, value: %s\n", key, buf);

	sleep(1);

	// remove test
	ret = syscall(223, HASH_DEL, "key1", NULL);
	printf("del key: %s, value: %s\n", key, value);
	*/

	assert(ret == 0);
	
	return 0;
}
