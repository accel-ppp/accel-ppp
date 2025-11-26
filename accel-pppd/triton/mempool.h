#ifndef __TRITON_MEMPOOL_H
#define __TRITON_MEMPOOL_H

#include <stdint.h>


typedef void * mempool_t;
mempool_t *mempool_create(int size);
mempool_t *mempool_create2(int size);

#ifdef MEMDEBUG
#include "memdebug.h"

void *md_mempool_alloc(mempool_t*, const char *fname, int line);
#define mempool_alloc(pool) md_mempool_alloc(pool, __FILE__, __LINE__)
#define mempool_free(ptr) md_free(ptr, __FILE__, __LINE__)
#else
void *mempool_alloc(mempool_t*);
void mempool_free(void*);
#endif

#endif

