#define _GNU_SOURCE
#include "mempool.h"
#include "logutils.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Memory pool structure */
struct memory_pool {
    void *free_list;       /* Head of free block linked list */
    size_t block_size;     /* Size of each block */
    size_t total_blocks;   /* Total number of blocks allocated */
    size_t free_blocks;    /* Number of available blocks */
    size_t max_blocks;     /* Maximum blocks allowed */
    size_t alloc_count;    /* Total allocations from pool */
    size_t free_count;     /* Total frees to pool */
    size_t bypass_allocs;  /* Large allocations bypassed to malloc */
    size_t bypass_frees;   /* Large frees bypassed to free */
};

/* Create memory pool */
memory_pool_t* mempool_create(size_t block_size, size_t initial_blocks, size_t max_blocks) {
    memory_pool_t *pool = malloc(sizeof(memory_pool_t));
    if (!pool) {
        LOGERR("[mempool] failed to allocate pool structure");
        return NULL;
    }
    
    /* Align block size to 64 bytes (cache line) for optimal performance */
    pool->block_size = (block_size + 63) & ~63;
    pool->max_blocks = (max_blocks == 0) ? SIZE_MAX : max_blocks;  /* 0 = unlimited */
    pool->total_blocks = 0;
    pool->free_blocks = 0;
    pool->free_list = NULL;
    pool->alloc_count = 0;
    pool->free_count = 0;
    pool->bypass_allocs = 0;
    pool->bypass_frees = 0;
    
    /* Pre-allocate initial blocks */
    for (size_t i = 0; i < initial_blocks; i++) {
        void *block = NULL;
        /* improved alignment for cache line (64 bytes) optimization */
        if (posix_memalign(&block, 64, pool->block_size) != 0) {
            LOGWAR("[mempool] failed to pre-allocate aligned block %zu/%zu", i, initial_blocks);
            break;
        }
        
        /* Insert into free list (using first bytes as next pointer) */
        *(void **)block = pool->free_list;
        pool->free_list = block;
        pool->total_blocks++;
        pool->free_blocks++;
    }
    
    LOG_ALWAYS_INF("[mempool] created: block_size=%zu, initial=%zu, max=%zu, memory=%zu KB", 
           pool->block_size, pool->total_blocks, pool->max_blocks,
           (pool->block_size * pool->total_blocks) / 1024);
    return pool;
}

/* Allocate memory with size awareness */
void* mempool_alloc_sized(memory_pool_t *pool, size_t size) {
    if (!pool) return NULL;
    
    /* Large packet bypass: direct malloc */
    if (size > pool->block_size) {
        pool->bypass_allocs++;
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
        if (pool->total_blocks < pool->max_blocks) {
            if (posix_memalign(&block, 64, pool->block_size) == 0) {
                pool->total_blocks++;
                LOGINF("[mempool] expanded: %zu/%zu", pool->total_blocks, pool->max_blocks);
            } else {
                LOGERR("[mempool] posix_memalign failed during expansion");
                return NULL;
            }
        } else {
            /* Pool exhausted, return NULL (caller handles this) */
            LOGWAR("[mempool] pool limit reached (%zu blocks), allocation failed", 
                   pool->total_blocks);
            return NULL;
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
size_t mempool_destroy(memory_pool_t *pool) {
    if (!pool) return 0;
    
    /* Calculate leaks */
    size_t pool_leaks = pool->alloc_count - pool->free_count;
    size_t bypass_leaks = pool->bypass_allocs - pool->bypass_frees;
    size_t total_leaks = pool_leaks + bypass_leaks;
    
    LOG_ALWAYS_INF("[mempool] destroy: total=%zu/%zu, free=%zu, alloc=%zu, free_ops=%zu, bypass_alloc=%zu, bypass_free=%zu, leaks=%zu", 
           pool->total_blocks, pool->max_blocks, pool->free_blocks, 
           pool->alloc_count, pool->free_count, 
           pool->bypass_allocs, pool->bypass_frees, total_leaks);
    
    if (total_leaks > 0) {
        LOGWAR("[mempool] detected leaks: pool=%zu, bypass=%zu", pool_leaks, bypass_leaks);
    }
    
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
    
    free(pool);
    return total_leaks;
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
