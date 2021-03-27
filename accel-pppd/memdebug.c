#undef MEMDEBUG

#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <signal.h>

#include "spinlock.h"
#include "list.h"

#define __init __attribute__((constructor))
#define __export __attribute__((visibility("default")))

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})


#define MAGIC1 UINT64_C(0x1122334455667788)

struct mem_t
{
	struct list_head entry;
	const char *fname;
	int line;
	size_t size;
	uint64_t magic2;
	uint64_t magic1;
	char data[0];
};

static LIST_HEAD(mem_list);
static spinlock_t mem_list_lock;

static struct mem_t *_md_malloc(size_t size, const char *fname, int line)
{
	struct mem_t *mem = malloc(sizeof(*mem) + size + 8);

	if (mem == NULL)
		return NULL;

	mem->fname = fname;
	mem->line = line;
	mem->size = size;
	mem->magic1 = MAGIC1;
	mem->magic2 = (uint64_t)random() * (uint64_t)random();
	*(uint64_t*)(mem->data + size) = mem->magic2;

	spin_lock(&mem_list_lock);
	list_add_tail(&mem->entry, &mem_list);
	spin_unlock(&mem_list_lock);

	return mem;
}

void __export *md_malloc(size_t size, const char *fname, int line)
{
	struct mem_t *mem = _md_malloc(size, fname, line);

	return mem ? mem->data : NULL;
}

void __export md_free(void *ptr, const char *fname, int line)
{
	struct mem_t *mem;

	if (!ptr)
		return;

	mem = container_of(ptr, typeof(*mem), data);

	if (mem->magic1 != MAGIC1) {
		printf("md_free: memory corruption:\nfree at %s:%i\n", fname, line);
		abort();
	}

	if (mem->magic2 != *(uint64_t*)(mem->data + mem->size)) {
		printf("md_free: memory corruption:\nmalloc(%zu) at %s:%i\nfree at %s:%i\n",
		       mem->size, mem->fname, mem->line, fname, line);
		abort();
	}

	mem->magic1 = 0;
	mem->magic2 = 0;

	spin_lock(&mem_list_lock);
	list_del(&mem->entry);
	spin_unlock(&mem_list_lock);

	free(mem);
	return;
}

void __export *md_realloc(void *ptr, size_t size, const char *fname, int line)
{
	struct mem_t *mem = ptr ? container_of(ptr, typeof(*mem), data) : NULL;
	struct mem_t *mem2;

	if (mem) {
		if (mem->magic1 != MAGIC1) {
			printf("md_realloc: memory corruption:\nfree at %s:%i\n",
			       fname, line);
			abort();
		}

		if (mem->magic2 != *(uint64_t*)(mem->data + mem->size)) {
			printf("md_realloc: memory corruption:\nmalloc(%zu) at %s:%i\nfree at %s:%i\n",
			       mem->size, mem->fname, mem->line, fname, line);
			abort();
		}

		if (size == 0) {
			md_free(mem->data, fname, line);
			return NULL;
		}
	}

	mem2 = _md_malloc(size, fname, line);
	if (mem2 == NULL)
		return NULL;

	if (mem) {
		memcpy(mem2->data, mem->data,
		       (size < mem->size) ? size : mem->size);
		md_free(mem->data, fname, line);
	}

	return mem2->data;
}

char __export *md_strdup(const char *ptr, const char *fname, int line)
{
	size_t len = strlen(ptr);
	char *str = md_malloc(len + 1, fname, line);

	if (str)
		memcpy(str, ptr, len + 1);

	return str;
}

char __export *md_strndup(const char *ptr, size_t n, const char *fname, int line)
{
	size_t len = strnlen(ptr, n);
	char *str = md_malloc(len + 1, fname, line);

	if (str) {
		memcpy(str, ptr, len);
		str[len] = '\0';
	}

	return str;
}

int __export md_asprintf(const char *fname, int line,
			 char **strp, const char *fmt, ...)
{
	va_list ap;
	va_list aq;
	int len;

	va_start(ap, fmt);
	va_copy(aq, ap);

	len = vsnprintf(NULL, 0, fmt, ap);
	if (len < 0)
		goto err;

	*strp = md_malloc(len + 1, fname, line);
	if (*strp == NULL)
		goto err;

	len = vsnprintf(*strp, len + 1, fmt, aq);
	if (len < 0)
		goto err_strp;

	va_end(aq);
	va_end(ap);

	return len;

err_strp:
	md_free(*strp, fname, line);
err:
	va_end(aq);
	va_end(ap);
	return -1;
}

static void siginfo(int num)
{
	struct mem_t *mem;
	size_t total = 0;

	spin_lock(&mem_list_lock);
	list_for_each_entry(mem, &mem_list, entry) {
		printf("%s:%i %lu\n", mem->fname, mem->line, (long unsigned)mem->size);
		total += mem->size;
	}
	spin_unlock(&mem_list_lock);
	printf("total = %lu\n", (long unsigned)total);
}

static void siginfo2(int num)
{
	struct mem_t *mem;

	spin_lock(&mem_list_lock);
	list_for_each_entry(mem, &mem_list, entry) {
		if (mem->magic1 != MAGIC1 || mem->magic2 != *(uint64_t*)(mem->data + mem->size))
			printf("%s:%i %lu\n", mem->fname, mem->line, (long unsigned)mem->size);
	}
	spin_unlock(&mem_list_lock);
}

void __export md_check(void *ptr)
{
	struct mem_t *mem = container_of(ptr, typeof(*mem), data);

	if (!ptr)
		abort();

	if (mem->magic1 != MAGIC1)
		abort();

	if (mem->magic2 != *(uint64_t*)(mem->data + mem->size))
		abort();
}

static void __init init(void)
{
	spinlock_init(&mem_list_lock);

	signal(36, siginfo);
	signal(37, siginfo2);
}
