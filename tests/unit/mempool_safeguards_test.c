/* Pool reuse must not expose the previous object's payload. */
#include <assert.h>
#include <pthread.h>
#include "triton.h"
#undef __init
#define __init
#include "../../accel-pppd/triton/mempool.c"

void triton_log_error(const char *fmt, ...) {}
void triton_stat_mempool_allocated_add(uint64_t v) {}
void triton_stat_mempool_allocated_sub(uint64_t v) {}
void triton_stat_mempool_available_add(uint64_t v) {}
void triton_stat_mempool_available_sub(uint64_t v) {}

int main(void)
{
	mempool_t *pool;
	unsigned char *p, *q;
	int i;

	spinlock_init(&pools_lock);
	pool = mempool_create(128);
	p = mempool_alloc(pool);
	assert(p);
	memset(p, 0xa5, 128);
	mempool_free(p);
	q = mempool_alloc(pool);
	assert(q == p);
	for (i = 0; i < 128; i++)
		assert(!q[i]);
	memset(q, 0x5a, 128);
	mempool_free(q);
	mempool_clean();
	list_del(&((struct _mempool_t *)pool)->entry);
	free(pool);
	puts("Mempool safeguards: PASS");
	return 0;
}
