/*
 * this is generic pool allocator
 * you should define following macroses:
 * ITEM_NAME - unique identifier, which allows to hold functions in a namespace
 * ITEM_TYPEDEF(name) - passed to typedef to localize item type
 * free_entry - desired name of function for free entry
 * alloc_entry - defired name of function for allocate entry
 */

#if POOL_ALLOC_PART == 1
#define DEFAULT_POOL_SIZE 8192
typedef unsigned int pool_free_counter;
typedef unsigned int pool_holder_counter;

typedef struct pool_entry_list pool_entry_list;
typedef struct pool_holder pool_holder;

typedef struct pool_free_pointer {
    pool_entry_list     *free;
    pool_free_counter    count;
    pool_holder_counter  size; // size of entry in sizeof(void*) items
    pool_holder_counter  total; // size of entry in sizeof(void*) items
} pool_free_pointer;

struct pool_entry_list {
    pool_entry_list *fore, *back;
};
#define ENTRY(ptr) ((pool_entry_list*)(ptr))
#define ENTRY_DATA_OFFSET offsetof(pool_entry_list, fore)
#define VOID2ENTRY(ptr) ENTRY((char*)(ptr) - ENTRY_DATA_OFFSET)
#define ENTRY2VOID(ptr) ((void*)((char*)(ptr) + ENTRY_DATA_OFFSET))

struct pool_holder {
    pool_holder_counter free, total;
    pool_holder_counter size;
    pool_free_pointer  *free_pointer;
    void *data[1];
};
#define POOL_DATA_SIZE(pool_size) (((pool_size) - sizeof(void*) * 6 - offsetof(pool_holder, data))/sizeof(void*))
#define POOL_HOLDER_SIZE (offsetof(pool_holder, data) + pointer->size*pointer->total*sizeof(void*))
#define POOL_ENTRY_SIZE(item_type) (((sizeof(item_type)+ENTRY_DATA_OFFSET-1)/sizeof(void*)+1))
#define POOL_HOLDER_COUNT(pool_size, item_type) (POOL_DATA_SIZE(pool_size)/POOL_ENTRY_SIZE(item_type))
#define INIT_POOL(item_type) {NULL, 0, POOL_ENTRY_SIZE(item_type), POOL_HOLDER_COUNT(DEFAULT_POOL_SIZE, item_type)}

#elif POOL_ALLOC_PART == 2
static void *
aligned_malloc(size_t alignment, size_t size)
{
    void *res;

#if __MINGW32__
    res = __mingw_aligned_malloc(size, alignment);
#elif _WIN32 || defined __CYGWIN__
    res = _aligned_malloc(size, alignment);
#elif defined(HAVE_POSIX_MEMALIGN)
    if (posix_memalign(&res, alignment, size) == 0) {
        return res;
    } else {
        return NULL;
    }
#elif defined(HAVE_MEMALIGN)
    res = memalign(alignment, size);
#else
#error no memalign function
#endif
    return res;
}

static void
aligned_free(void *ptr)
{
#if __MINGW32__
    __mingw_aligned_free(ptr);
#elif _WIN32 || defined __CYGWIN__
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

static void
pool_holder_alloc(pool_free_pointer *pointer)
{
    pool_holder *holder;
    pool_holder_counter i, size, count;
    register void **ptr;

    size_t sz = offsetof(pool_holder, data) +
	    pointer->size * pointer->total * sizeof(void*);
#define objspace (&rb_objspace)
    vm_malloc_prepare(objspace, DEFAULT_POOL_SIZE - sizeof(size_t));
    if (pointer->free != NULL) return;
    TRY_WITH_GC(holder = (pool_holder*) aligned_malloc(DEFAULT_POOL_SIZE, sz));
    malloc_increase += DEFAULT_POOL_SIZE;
#if CALC_EXACT_MALLOC_SIZE
    objspace->malloc_params.allocated_size += DEFAULT_POOL_SIZE;
    objspace->malloc_params.allocations++;
#endif
#undef objspace

    size = pointer->size;
    count = pointer->total;
    holder->free = count;
    holder->total = count;
    holder->size = size;
    holder->free_pointer = pointer;
    ptr = holder->data;
    ENTRY(ptr)->back = NULL;
    for(i = count - 1; i; i-- ) {
        ENTRY(ptr)->fore = ENTRY(ptr + size);
        ENTRY(ptr + size)->back = ENTRY(ptr);
	ptr += size;
    }
    ENTRY(ptr)->fore = pointer->free;
    pointer->free = ENTRY(holder->data);
    pointer->count += count;
}

static void
pool_holder_free(pool_holder *holder)
{
    void **ptr = holder->data;
    pool_free_pointer *pointer = holder->free_pointer;
    pool_holder_counter i, size, total;

    size = holder->size;
    total = holder->total;

    for(i = total; i; i--) {
	register pool_entry_list
	    *fore = ENTRY(ptr)->fore,
	    *back = ENTRY(ptr)->back;

	if (fore)  fore->back    = back;
	if (back)  back->fore    = fore;
	else       pointer->free = fore;
	ptr += size;
    }
    pointer->count-= total;

    aligned_free(holder);
#if CALC_EXACT_MALLOC_SIZE
    rb_objspace.malloc_params.allocated_size += DEFAULT_POOL_SIZE;
    rb_objspace.malloc_params.allocations++;
#endif
}

static inline pool_holder *
entry_holder(pool_entry_list *entry)
{
    return (pool_holder*)(((uintptr_t)entry) & ~(DEFAULT_POOL_SIZE - 1));
}

static inline void
pool_free_entry(pool_entry_list *entry)
{
    pool_holder *holder = entry_holder(entry);
    pool_free_pointer *pointer = holder->free_pointer;
    register pool_entry_list *free;
    entry->back = NULL;
    entry->fore = (free = pointer->free);
    pointer->free = entry;
    if (free) { free->back = entry; }
    holder->free++;
    if (holder->free == holder->total) {
        pool_holder_free(holder);
    }
}

static inline pool_entry_list *
pool_alloc_entry(pool_free_pointer *pointer)
{
    pool_entry_list *result;
    if (pointer->free == NULL) {
        pool_holder_alloc(pointer);
    }
    result = pointer->free;
    pointer->free = result->fore;
    entry_holder(result)->free--;
    return result;
}

static inline void
pool_free(void *p)
{
    pool_free_entry(VOID2ENTRY(p));
}

static inline void*
pool_alloc(pool_free_pointer *pointer)
{
    return ENTRY2VOID(pool_alloc_entry(pointer));
}
#endif
