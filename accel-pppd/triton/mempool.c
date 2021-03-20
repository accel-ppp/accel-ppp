#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/mman.h>

#include "triton_p.h"

#include "memdebug.h"

#ifdef VALGRIND
#include <valgrind/memcheck.h>
#define DELAY 5
#endif

//#define MEMPOOL_DISABLE

#define MAGIC1 0x2233445566778899llu
#define PAGE_ORDER 5

static int conf_mempool_min = 128;

struct _mempool_t
{
	struct list_head entry;
	int size;
	struct list_head items;
#ifdef MEMDEBUG
	struct list_head ditems;
	uint64_t magic;
#endif
	spinlock_t lock;
	unsigned int mmap:1;
	int objects;
};

struct _item_t
{
	struct list_head entry;
#ifdef VALGRIND
	time_t timestamp;
#endif
	struct _mempool_t *owner;
#ifdef MEMDEBUG
	const char *fname;
	int line;
	uint64_t magic2;
	uint64_t magic1;
#endif
	char ptr[0];
};

static LIST_HEAD(pools);
static spinlock_t pools_lock;
static spinlock_t mmap_lock;
static uint8_t *mmap_ptr;
static uint8_t *mmap_endptr;

static int mmap_grow(void);
static void mempool_clean(void);

mempool_t __export *mempool_create(int size)
{
	struct _mempool_t *p = _malloc(sizeof(*p));

	memset(p, 0, sizeof(*p));
	INIT_LIST_HEAD(&p->items);
#ifdef MEMDEBUG
	INIT_LIST_HEAD(&p->ditems);
	p->magic = (uint64_t)random() * (uint64_t)random();
#endif
	spinlock_init(&p->lock);
	p->size = size;

	spin_lock(&pools_lock);
	list_add_tail(&p->entry, &pools);
	spin_unlock(&pools_lock);

	return (mempool_t *)p;
}

mempool_t __export *mempool_create2(int size)
{
	struct _mempool_t *p = (struct _mempool_t *)mempool_create(size);

	p->mmap = 1;

	return (mempool_t *)p;
}

#ifndef MEMDEBUG
void __export *mempool_alloc(mempool_t *pool)
{
	struct _mempool_t *p = (struct _mempool_t *)pool;
	struct _item_t *it;
	uint32_t size = sizeof(*it) + p->size + 8;

	spin_lock(&p->lock);
	if (!list_empty(&p->items)) {
		it = list_entry(p->items.next, typeof(*it), entry);
		list_del(&it->entry);
		spin_unlock(&p->lock);

		--p->objects;
		__sync_sub_and_fetch(&triton_stat.mempool_available, size);

		return it->ptr;
	}
	spin_unlock(&p->lock);

	if (p->mmap) {
		spin_lock(&mmap_lock);
		if (mmap_ptr + size >= mmap_endptr) {
			if (mmap_grow()) {
				spin_unlock(&mmap_lock);
				return NULL;
			}
		}
		it = (struct _item_t *)mmap_ptr;
		mmap_ptr += size;
		spin_unlock(&mmap_lock);
		__sync_sub_and_fetch(&triton_stat.mempool_available, size);
	} else {
		it = _malloc(size);
		__sync_add_and_fetch(&triton_stat.mempool_allocated, size);
	}

	if (!it) {
		triton_log_error("mempool: out of memory");
		return NULL;
	}
	it->owner = p;

	return it->ptr;
}

void __export mempool_free(void *ptr)
{
	struct _item_t *it = container_of(ptr, typeof(*it), ptr);
	struct _mempool_t *p = it->owner;
	uint32_t size = sizeof(*it) + it->owner->size + 8;
	int need_free = 0;

#ifdef MEMDEBUG
	if (it->magic1 != MAGIC1) {
		triton_log_error("mempool: memory corruption detected");
		abort();
	}

	if (it->magic2 != it->owner->magic) {
		triton_log_error("mempool: memory corruption detected");
		abort();
	}

	if (it->magic2 != *(uint64_t*)(it->ptr + it->owner->size)) {
		triton_log_error("mempool: memory corruption detected");
		abort();
	}

	it->magic1 = 0;
#endif

	spin_lock(&p->lock);
#ifdef MEMDEBUG
	list_del(&it->entry);
#endif
#ifndef MEMPOOL_DISABLE
	if (p->objects < conf_mempool_min) {
		++p->objects;
		list_add_tail(&it->entry,&it->owner->items);
	} else
		need_free = 1;
#endif
#ifdef VALGRIND
	time(&it->timestamp);
	VALGRIND_MAKE_MEM_NOACCESS(&it->owner, size - sizeof(it->entry) - sizeof(it->timestamp));
#endif
	spin_unlock(&p->lock);

#ifdef MEMPOOL_DISABLE
	_free(it);
#else
	if (need_free) {
		_free(it);
		__sync_sub_and_fetch(&triton_stat.mempool_allocated, size);
	} else
		__sync_add_and_fetch(&triton_stat.mempool_available, size);
#endif

}


#else

void __export *md_mempool_alloc(mempool_t *pool, const char *fname, int line)
{
	struct _mempool_t *p = (struct _mempool_t *)pool;

	return md_malloc(p->size, fname, line);
}
#endif


#ifdef MEMDEBUG
void __export mempool_show(mempool_t *pool)
{
	struct _mempool_t *p = (struct _mempool_t *)pool;
	struct _item_t *it;

	spin_lock(&p->lock);
	list_for_each_entry(it, &p->ditems, entry)
		triton_log_error("%s:%i %p\n", it->fname, it->line, it->ptr);
	spin_unlock(&p->lock);
}
#endif

static void mempool_clean(void)
{
	struct _mempool_t *p;
	struct _item_t *it;
	uint32_t size;

	triton_log_error("mempool: clean");

	spin_lock(&pools_lock);
	list_for_each_entry(p, &pools, entry) {
		if (p->mmap)
			continue;
		size = sizeof(*it) + p->size + 8;
		spin_lock(&p->lock);
		while (!list_empty(&p->items)) {
			it = list_entry(p->items.next, typeof(*it), entry);
#ifdef VALGRIND
			if (it->timestamp + DELAY < time(NULL)) {
			VALGRIND_MAKE_MEM_DEFINED(&it->owner, size - sizeof(it->entry) - sizeof(it->timestamp));
#endif
			list_del(&it->entry);
			_free(it);
			__sync_sub_and_fetch(&triton_stat.mempool_allocated, size);
			__sync_sub_and_fetch(&triton_stat.mempool_available, size);
#ifdef VALGRIND
			} else
				break;
#endif
		}
		spin_unlock(&p->lock);
	}
	spin_unlock(&pools_lock);
}

static void sigclean(int num)
{
	mempool_clean();
}

static int mmap_grow(void)
{
	int size = sysconf(_SC_PAGESIZE) * (1 << PAGE_ORDER);
	uint8_t *ptr;

	if (mmap_endptr) {
		ptr = mmap(mmap_endptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		if (ptr == MAP_FAILED)
			goto oom;
		if (ptr != mmap_endptr)
			mmap_ptr = ptr;
	} else {
		ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		if (ptr == MAP_FAILED)
			goto oom;
		mmap_ptr = ptr;
	}

	mmap_endptr = ptr + size;

	__sync_add_and_fetch(&triton_stat.mempool_allocated, size);
	__sync_add_and_fetch(&triton_stat.mempool_available, size);

	return 0;
oom:
	triton_log_error("mempool: out of memory");
	return -1;
}

static void __init init(void)
{
	sigset_t set;
	sigfillset(&set);

	spinlock_init(&pools_lock);
	spinlock_init(&mmap_lock);

	struct sigaction sa = {
		.sa_handler = sigclean,
		.sa_mask = set,
	};

	sigaction(35, &sa, NULL);

	mmap_grow();
}

