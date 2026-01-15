#define _GNU_SOURCE
#include "mempool.h"
#include "logutils.h"
#include <stdlib.h>
#include <string.h>

/* Memory pool configuration */
#define POOL_MAX_SIZE 2048  /* Maximum blocks per pool (4MB at 2KB/block) */

/* Memory pool structure */
struct memory_pool {
    void *free_list;       /* Head of free block linked list */
    size_t block_size;     /* Size of each block */
    size_t total_blocks;   /* Total number of blocks allocated */
    size_t free_blocks;    /* Number of available blocks */
    size_t alloc_count;    /* Total allocations from pool */
    size_t free_count;     /* Total frees to pool */
    size_t bypass_allocs;  /* Large allocations bypassed to malloc */
    size_t bypass_frees;   /* Large frees bypassed to free */
};

/* Create memory pool */
memory_pool_t* mempool_create(size_t block_size, size_t initial_blocks) {
    memory_pool_t *pool = malloc(sizeof(memory_pool_t));
    if (!pool) {
        LOGERR("[mempool] failed to allocate pool structure");
        return NULL;
    }
    
    pool->block_size = block_size;
    pool->total_blocks = 0;
    pool->free_blocks = 0;
    pool->free_list = NULL;
    pool->alloc_count = 0;
    pool->free_count = 0;
    pool->bypass_allocs = 0;
    pool->bypass_frees = 0;
    
    /* Pre-allocate initial blocks */
    for (size_t i = 0; i < initial_blocks; i++) {
        void *block = malloc(block_size);
        if (!block) {
            LOGWAR("[mempool] failed to pre-allocate block %zu/%zu", i, initial_blocks);
            break;
        }
        
        /* Insert into free list (using first bytes as next pointer) */
        *(void **)block = pool->free_list;
        pool->free_list = block;
        pool->total_blocks++;
        pool->free_blocks++;
    }
    
    LOG_ALWAYS_INF("[mempool] created: block_size=%zu, initial_blocks=%zu, memory=%zu KB", 
           block_size, pool->total_blocks, (block_size * pool->total_blocks) / 1024);
    return pool;
}

/* Allocate memory with size awareness */
void* mempool_alloc_sized(memory_pool_t *pool, size_t size) {
    if (!pool) return NULL;
    
    /* Large packet bypass: direct malloc */
    if (size > pool->block_size) {
        pool->bypass_allocs++;
        LOGINF("[mempool] large packet %zu bytes, bypass to malloc (total: %zu)", 
               size, pool->bypass_allocs);
        return malloc(size);
    }
    
    void *block = NULL;
    
    /* Try to get from free list */
    if (pool->free_list) {
        block = pool->free_list;
        pool->free_list = *(void **)block;
        pool->free_blocks--;
    } else {
        /* Free list empty, try dynamic expansion */
        if (pool->total_blocks < POOL_MAX_SIZE) {
            block = malloc(pool->block_size);
            if (block) {
                pool->total_blocks++;
                LOGINF("[mempool] expanded: total_blocks=%zu", pool->total_blocks);
            } else {
                LOGERR("[mempool] malloc failed during expansion");
                return NULL;
            }
        } else {
            /* Pool exhausted, fallback to malloc */
            LOGWAR("[mempool] pool limit reached (%zu blocks), fallback to malloc", 
                   pool->total_blocks);
            pool->bypass_allocs++;
            return malloc(size);
        }
    }
    
    pool->alloc_count++;
    return block;
}

/* Free memory with size awareness */
void mempool_free_sized(memory_pool_t *pool, void *block, size_t size) {
    if (!pool || !block) return;
    
    /* Large packet bypass: direct free */
    if (size > pool->block_size) {
        pool->bypass_frees++;
        free(block);
        return;
    }
    
    /* Return block to free list */
    *(void **)block = pool->free_list;
    pool->free_list = block;
    pool->free_blocks++;
    pool->free_count++;
}

/* Destroy memory pool */
void mempool_destroy(memory_pool_t *pool) {
    if (!pool) return;
    
    LOG_ALWAYS_INF("[mempool] destroy: total=%zu, free=%zu, alloc=%zu, free_ops=%zu, bypass_alloc=%zu, bypass_free=%zu", 
           pool->total_blocks, pool->free_blocks, pool->alloc_count, 
           pool->free_count, pool->bypass_allocs, pool->bypass_frees);
    
    /* Free all blocks in free list */
    void *curr = pool->free_list;
    size_t freed = 0;
    while (curr) {
        void *next = *(void **)curr;
        free(curr);
        freed++;
        curr = next;
    }
    
    if (freed != pool->free_blocks) {
        LOGWAR("[mempool] freed %zu blocks but free_blocks was %zu", freed, pool->free_blocks);
    }
    
    /* Check for memory leaks */
    size_t outstanding = pool->alloc_count - pool->free_count;
    if (outstanding > 0) {
        LOGWAR("[mempool] potential leak: %zu blocks not freed", outstanding);
    }
    
    free(pool);
}

/* Get statistics */
void mempool_get_stats(memory_pool_t *pool, size_t *total_blocks, 
                       size_t *free_blocks, size_t *alloc_count, 
                       size_t *free_count) {
    if (!pool) return;
    if (total_blocks) *total_blocks = pool->total_blocks;
    if (free_blocks) *free_blocks = pool->free_blocks;
    if (alloc_count) *alloc_count = pool->alloc_count;
    if (free_count) *free_count = pool->free_count;
}
