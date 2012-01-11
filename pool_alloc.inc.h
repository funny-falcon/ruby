/*
 * this is generic pool allocator
 * you should define following macroses:
 * ITEM_NAME - unique identifier, which allows to hold functions in a namespace
 * ITEM_TYPEDEF(name) - passed to typedef to localize item type
 * free_entry - desired name of function for free entry
 * alloc_entry - defired name of function for allocate entry
 */

#if POOL_ALLOC_PART == 1

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
    pool_holder *holder;
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
#define POOL_DATA_SIZE(pool_size) (((pool_size) - sizeof(void*) * 3 - offsetof(pool_holder, data))/sizeof(void*))
#define POOL_HOLDER_SIZE (offsetof(pool_holder, data) + pointer->size*pointer->total*sizeof(void*))
#define POOL_ENTRY_SIZE(item_type) (((sizeof(item_type)+ENTRY_DATA_OFFSET-1)/sizeof(void*)+1))
#define POOL_HOLDER_COUNT(pool_size, item_type) (POOL_DATA_SIZE(pool_size)/POOL_ENTRY_SIZE(item_type))
#define INIT_POOL(pool_size, item_type) {NULL, 0, POOL_ENTRY_SIZE(item_type), POOL_HOLDER_COUNT(pool_size, item_type)}

#elif POOL_ALLOC_PART == 2

static void
pool_holder_alloc(pool_free_pointer *pointer)
{
    pool_holder *holder;
    pool_holder_counter i, size, count;
    register void **ptr;

    size_t sz = vm_malloc_prepare(&rb_objspace,
	    offsetof(pool_holder, data) +
	    pointer->size * pointer->total * sizeof(void*));
    if (pointer->free != NULL) return;
#define objspace (&rb_objspace)
    TRY_WITH_GC(holder = (pool_holder*)malloc(sz));
#undef objspace
    holder = vm_malloc_fixup(&rb_objspace, holder, sz);

    size = pointer->size;
    count = pointer->total;
    holder->free = count;
    holder->total = count;
    holder->size = size;
    holder->free_pointer = pointer;
    ptr = holder->data;
    ENTRY(ptr)->back = NULL;
    for(i = count - 1; i; i-- ) {
        ENTRY(ptr)->holder = holder;
        ENTRY(ptr)->fore = ENTRY(ptr + size);
        ENTRY(ptr + size)->back = ENTRY(ptr);
	ptr += size;
    }
    ENTRY(ptr)->holder = holder;
    ENTRY(ptr)->fore = pointer->free;
    pointer->free = ENTRY(holder->data);
    pointer->count += count;
}

static void
pool_holder_free(pool_holder *holder)
{
    pool_holder_counter i, size;
    void **ptr = holder->data;
    pool_free_pointer *pointer = holder->free_pointer;
    size = holder->size;

    for(i = holder->total; i; i--) {
	if (ENTRY(ptr)->fore) {
	    ENTRY(ptr)->fore->back = ENTRY(ptr)->back;
	}
	if (ENTRY(ptr)->back) {
	    ENTRY(ptr)->back->fore = ENTRY(ptr)->fore;
	} else {
	    pointer->free = ENTRY(ptr)->fore;
	}
	ptr += size;
    }
    pointer->count-= holder->total;
    vm_xfree(&rb_objspace, holder);
}

static inline void
pool_free_entry(pool_entry_list *entry)
{
    pool_holder *holder = entry->holder;
    pool_free_pointer *pointer = holder->free_pointer;
    entry->fore = pointer->free;
    entry->back = NULL;
    if (pointer->free) {
	pointer->free->back = entry;
    }
    pointer->free = entry;
    pointer->count++;
    holder->free++;
    if (holder->free == holder->total) {
        pool_holder_free(entry->holder);
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
    pointer->count--;
    result->holder->free--;
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
