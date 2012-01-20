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
typedef unsigned int pool_holder_counter;

typedef struct pool_entry_list pool_entry_list;
typedef struct pool_holder pool_holder;

typedef struct pool_free_pointer {
    pool_holder         *first;
    pool_holder         *_black_magick;
    pool_holder_counter  size; // size of entry in sizeof(void*) items
    pool_holder_counter  total; // size of entry in sizeof(void*) items
} pool_free_pointer;

struct pool_holder {
    pool_holder_counter free, total;
    pool_free_pointer  *free_pointer;
    void               *freep;
    pool_holder        *fore, *back;
    void *data[1];
};
#define POOL_DATA_SIZE(pool_size) (((pool_size) - sizeof(void*) * 6 - offsetof(pool_holder, data)) / sizeof(void*))
#define POOL_ENTRY_SIZE(item_type) ((sizeof(item_type) - 1) / sizeof(void*) + 1)
#define POOL_HOLDER_COUNT(pool_size, item_type) (POOL_DATA_SIZE(pool_size)/POOL_ENTRY_SIZE(item_type))
#define INIT_POOL(item_type) {NULL, NULL, POOL_ENTRY_SIZE(item_type), POOL_HOLDER_COUNT(DEFAULT_POOL_SIZE, item_type)}

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

static pool_holder *
pool_holder_alloc(pool_free_pointer *pointer)
{
    pool_holder *holder;
    pool_holder_counter i, size, count;
    register void **ptr;

    size_t sz = offsetof(pool_holder, data) +
	    pointer->size * pointer->total * sizeof(void*);
#define objspace (&rb_objspace)
    vm_malloc_prepare(objspace, DEFAULT_POOL_SIZE - sizeof(size_t));
    if (pointer->first != NULL) return pointer->first;
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
    holder->free_pointer = pointer;
    holder->fore = NULL;
    holder->back = NULL;
    holder->freep = &holder->data;
    ptr = holder->data;
    for(i = count - 1; i; i-- ) {
	ptr = *ptr = ptr + size;
    }
    *ptr = NULL;
    pointer->first = holder;
    return holder;
}

static inline void
pool_holder_unchaing(pool_free_pointer *pointer, pool_holder *holder)
{
    register pool_holder *fore = holder->fore, *back = holder->back;
    holder->fore = NULL;
    holder->back = NULL;
    if (fore != NULL)  fore->back     = back;
    else               pointer->_black_magick = back;
    if (back != NULL)  back->fore     = fore;
    else               pointer->first = fore;
}

static inline pool_holder *
entry_holder(void **entry)
{
    return (pool_holder*)(((uintptr_t)entry) & ~(DEFAULT_POOL_SIZE - 1));
}

static inline void
pool_free_entry(void **entry)
{
    pool_holder *holder = entry_holder(entry);
    pool_free_pointer *pointer = holder->free_pointer;

    if (holder->free++ == 0) {
	register pool_holder *first = pointer->first;
	if (first == NULL) {
	    pointer->first = holder;
	} else {
	    holder->back = first;
	    holder->fore = first->fore;
	    first->fore = holder;
	    if (holder->fore)
		holder->fore->back = holder;
	    else
		pointer->_black_magick = holder;
	}
    } else if (holder->free == holder->total && pointer->first != holder ) {
	pool_holder_unchaing(pointer, holder);
	aligned_free(holder);
#if CALC_EXACT_MALLOC_SIZE
	rb_objspace.malloc_params.allocated_size -= DEFAULT_POOL_SIZE;
	rb_objspace.malloc_params.allocations--;
#endif
	return;
    }

    *entry = holder->freep;
    holder->freep = entry;
}

static inline void*
pool_alloc_entry(pool_free_pointer *pointer)
{
    pool_holder *holder = pointer->first;
    void **result;
    if (holder == NULL) {
	holder = pool_holder_alloc(pointer);
    }

    result = holder->freep;
    holder->freep = *result;

    if (--holder->free == 0) {
	pool_holder_unchaing(pointer, holder);
    }

    return result;
}

static inline void
pool_free(void *p)
{
    pool_free_entry((void **)p);
}

static inline void*
pool_alloc(pool_free_pointer *pointer)
{
    return pool_alloc_entry(pointer);
}
#endif
