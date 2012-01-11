#ifndef POOL_ALLOC_H
#define POOL_ALLOC_H

#define POOL_ALLOC_API
#ifdef POOL_ALLOC_API
void *ruby_xpool_malloc(size_t size);
void *ruby_xpool_malloc2(size_t count, size_t size);
void  ruby_xpool_free(void *ptr);
void *ruby_xpool_realloc(void* ptr, size_t size);
void *ruby_xpool_realloc2(void* ptr, size_t count, size_t size);
void *ruby_xpool_calloc(size_t count, size_t size);
void *ruby_xpool_malloc_6p();
void *ruby_xpool_malloc_11p();
void *ruby_xpool_malloc_19p();
void *ruby_xpool_malloc_32p();
#if SIZEOF_VOIDP == 4
#define ruby_xpool_malloc_128b ruby_xpool_malloc_32p
#elif SIZEOF_VOIDP == 8
#define ruby_xpool_malloc_128b ruby_xpool_malloc_19p
#endif
#endif

#endif
