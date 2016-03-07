/* This is a public domain general purpose hash table package written by Peter Moore @ UCB. */

/* static	char	sccsid[] = "@(#) st.c 5.1 89/12/14 Crucible"; */

#ifdef NOT_RUBY
#include "regint.h"
#include "st.h"
#else
#include "internal.h"
#endif

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include "ccan/list/list.h"

typedef struct st_table_entry st_table_entry;

struct st_table_entry {
    st_idx_t hash;
    st_idx_t next;
    st_data_t key;
    st_data_t record;
    st_idx_t prev, forw;
};

#ifndef STATIC_ASSERT
#define STATIC_ASSERT(name, expr) typedef int static_assert_##name##_check[(expr) ? 1 : -1]
#endif

    /*
     * DEFAULT_MAX_DENSITY is the default for the largest we allow the
     * average number of items per bin before increasing the number of
     * bins
     *
     * DEFAULT_INIT_TABLE_SIZE is the default for the number of bins
     * allocated initially
     *
     */

#define type_numhash st_hashtype_num
const struct st_hash_type st_hashtype_num = {
    st_numcmp,
    st_numhash,
};

/* extern int strcmp(const char *, const char *); */
static st_index_t strhash(st_data_t);
static const struct st_hash_type type_strhash = {
    strcmp,
    strhash,
};

static st_index_t strcasehash(st_data_t);
static const struct st_hash_type type_strcasehash = {
    st_locale_insensitive_strcasecmp,
    strcasehash,
};

static void rehash(st_table *);

#ifdef RUBY
#define malloc ruby_xmalloc
#define calloc ruby_xcalloc
#define sized_realloc(p, new, old) ruby_sized_xrealloc((p), (new), (old))
#define sized_free(p, sz) ruby_sized_xfree((p), (sz))
#else
#error "NOT RUBY"
#define sized_realloc(p, new, old) realloc((p), (new))
#define sized_free(p, sz) free(p)
#endif

#define IDX_NULL ((st_idx_t)0xffffffff)
#define Z ((ssize_t)-1)

/* preparation for possible allocation improvements */
#define st_alloc_table() (st_table *)calloc(1, sizeof(st_table))
#define st_dealloc_table(table) sized_free(table, sizeof(st_table))

/* this calculation to satisfy jemalloc/tcmalloc allocation sizes */
#define DIVIDER (sizeof(st_table_entry)/sizeof(st_idx_t))
#if SIZEOF_VOIDP == 8
#define SIZE(ent, bins) {ent - (bins / DIVIDER), bins-1 }
#else
#define SIZE(ent, bins) {ent - (bins / DIVIDER + 1), bins-1 }
#endif
static struct st_sizes {
    st_idx_t nentries, bin_mask;
} const st_sz[] = {
    { 0, 0 },
#if SIZEOF_VOIDP > 4
    { 0x3, 0x7 }, { 0x5, 0x7 }, { 0x7, 0x7 }, { 0xb, 0x7},
#else
    { 0x3, 0x3 }, { 0x5, 0x3 }, { 0x7, 0x3 },
#endif
    SIZE(0x10, 0x10), SIZE(0x18, 0x10),
    SIZE(0x20, 0x20), SIZE(0x30, 0x20),
    SIZE(0x40, 0x40), SIZE(0x60, 0x40),
    SIZE(0x80, 0x80), SIZE(0xc0, 0x80),
    SIZE(0x100, 0x100), SIZE(0x180, 0x100),
    SIZE(0x200, 0x200), SIZE(0x300, 0x200),
    SIZE(0x400, 0x400), SIZE(0x600, 0x400),
    SIZE(0x800, 0x800), SIZE(0xc00, 0x800),
    SIZE(0x1000, 0x1000), SIZE(0x1800, 0x1000),
    SIZE(0x2000, 0x2000), SIZE(0x3000, 0x2000),
    SIZE(0x4000, 0x4000), SIZE(0x6000, 0x4000),
    SIZE(0x8000, 0x8000), SIZE(0xc000, 0x8000),
    SIZE(0x10000, 0x10000), SIZE(0x18000, 0x10000),
    SIZE(0x20000, 0x20000), SIZE(0x30000, 0x20000),
    SIZE(0x40000, 0x40000), SIZE(0x60000, 0x40000),
    SIZE(0x80000, 0x80000), SIZE(0xc0000, 0x80000),
    SIZE(0x100000, 0x100000), SIZE(0x180000, 0x100000),
    SIZE(0x200000, 0x200000), SIZE(0x300000, 0x200000),
    SIZE(0x400000, 0x400000), SIZE(0x600000, 0x400000),
    SIZE(0x800000, 0x800000), SIZE(0xc00000, 0x800000),
    SIZE(0x1000000, 0x1000000), SIZE(0x1800000, 0x1000000),
    SIZE(0x2000000, 0x2000000), SIZE(0x3000000, 0x2000000),
    SIZE(0x4000000, 0x4000000), SIZE(0x6000000, 0x4000000),
#if SIZEOF_VOIDP > 4
    SIZE(0x8000000, 0x8000000), SIZE(0xc000000, 0x8000000),
    SIZE(0x10000000, 0x10000000), SIZE(0x18000000, 0x10000000),
    SIZE(0x20000000, 0x20000000), SIZE(0x30000000, 0x20000000),
    SIZE(0x40000000, 0x40000000), SIZE(0x60000000, 0x40000000),
    SIZE(0x80000000, 0x80000000), SIZE(0xc0000000, 0x80000000),
    SIZE(0xfffffffe, 0x80000000),
#endif
    { 0, 0 }
};

#define do_hash(key,table) (st_index_t)(*(table)->type->hash)((key))
#define hash_pos(h,sz) ((h) & st_sz[sz].bin_mask)

static inline size_t
entries_size(int sz)
{
    return (st_sz[sz].bin_mask+1)*sizeof(st_idx_t) + st_sz[sz].nentries*sizeof(st_table_entry);
}

static inline st_idx_t*
base_ptr(st_table_entry* e, int sz)
{
    return (st_idx_t*)e - ((ssize_t)st_sz[sz].bin_mask+1);
}

static inline st_table_entry*
entries_ptr(st_idx_t* e, int sz)
{
    return (st_table_entry*)(e + (st_sz[sz].bin_mask+1));
}

static st_idx_t fake_bins[2] = { IDX_NULL, IDX_NULL };

static st_table_entry*
st_alloc_data(int sz)
{
    if (sz != 0) {
	st_idx_t i, nen = st_sz[sz].nentries;
	st_idx_t* bins = (st_idx_t*)calloc(1, entries_size(sz));
	st_table_entry* en;
	memset(bins, 0xff, (st_sz[sz].bin_mask + 1)*sizeof(st_idx_t));
	en = entries_ptr(bins, sz);
	for (i = 0; i < nen-1; i++) {
	    en[i].next = i+1;
	}
	en[nen-1].next = IDX_NULL;
	return en;
    } else {
	return (st_table_entry*)(fake_bins + 1);
    }
}

static inline void
st_free_data(st_table_entry* entries, int sz)
{
    if (sz != 0) {
	sized_free(base_ptr(entries, sz), entries_size(sz));
    }
}

static inline st_table_entry*
st_grow_data(st_table_entry *e, int newsz, int oldsz)
{
    if (oldsz == 0) {
	return st_alloc_data(newsz);
    } else {
	st_idx_t* bins = base_ptr(e, oldsz);
	st_idx_t i;
	st_idx_t en_old = st_sz[oldsz].nentries;
	st_idx_t en_new = st_sz[newsz].nentries;
	st_idx_t bins_old = st_sz[oldsz].bin_mask + 1;
	st_idx_t bins_new = st_sz[newsz].bin_mask + 1;
	st_table_entry* en;
	bins = sized_realloc(bins, entries_size(newsz), entries_size(oldsz));
	if (bins == NULL) {
#ifndef NOT_RUBY
	    rb_raise(rb_eNoMemError, "no memory");
#else
	    return NULL;
#endif
	}
	if (bins_old < bins_new) {
	    MEMMOVE(bins + bins_new, bins + bins_old, st_table_entry, st_sz[oldsz].nentries);
	    memset(bins, 0xff, bins_new*sizeof(st_idx_t));
	}
	en = entries_ptr(bins, newsz);
	for (i = en_old; i < en_new-1; i++) {
	    en[i].next = i+1;
	}
	en[en_new-1].next = IDX_NULL;
	return en;
    }
}

static int
new_sz(st_idx_t size)
{
    int i;
    if (size == 0) return 0;
    for (i = 1; st_sz[i].nentries != 0; i++)
        if (st_sz[i].nentries >= size)
            return i;
#ifndef NOT_RUBY
    rb_raise(rb_eRuntimeError, "st_table too big");
#endif
    return -1;			/* should raise exception */
}

#ifdef HASH_LOG
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
static struct {
    int all, total, num, str, strcase;
}  collision;
static int init_st = 0;

static void
stat_col(void)
{
    char fname[10+sizeof(long)*3];
    FILE *f = fopen((snprintf(fname, sizeof(fname), "/tmp/col%ld", (long)getpid()), fname), "w");
    fprintf(f, "collision: %d / %d (%6.2f)\n", collision.all, collision.total,
	    ((double)collision.all / (collision.total)) * 100);
    fprintf(f, "num: %d, str: %d, strcase: %d\n", collision.num, collision.str, collision.strcase);
    fclose(f);
}
#endif

st_table*
st_init_table_with_size(const struct st_hash_type *type, st_index_t size)
{
    st_table *tbl;

#ifdef HASH_LOG
# if HASH_LOG+0 < 0
    {
	const char *e = getenv("ST_HASH_LOG");
	if (!e || !*e) init_st = 1;
    }
# endif
    if (init_st == 0) {
	init_st = 1;
	atexit(stat_col);
    }
#endif

    tbl = st_alloc_table();
    tbl->type = type;
    tbl->num_entries = 0;
    tbl->sz = new_sz(size);	/* round up to power-of-two */
    tbl->first = IDX_NULL;
    if (tbl->sz > 0) {
	tbl->as.entries = st_alloc_data(tbl->sz);
	tbl->free = 0;
    } else {
	tbl->as.bins = &fake_bins[1];
	tbl->free = IDX_NULL;
    }

    return tbl;
}

st_table*
st_init_table(const struct st_hash_type *type)
{
    return st_init_table_with_size(type, 0);
}

st_table*
st_init_numtable(void)
{
    return st_init_table(&type_numhash);
}

st_table*
st_init_numtable_with_size(st_index_t size)
{
    return st_init_table_with_size(&type_numhash, size);
}

st_table*
st_init_strtable(void)
{
    return st_init_table(&type_strhash);
}

st_table*
st_init_strtable_with_size(st_index_t size)
{
    return st_init_table_with_size(&type_strhash, size);
}

st_table*
st_init_strcasetable(void)
{
    return st_init_table(&type_strcasehash);
}

st_table*
st_init_strcasetable_with_size(st_index_t size)
{
    return st_init_table_with_size(&type_strcasehash, size);
}

void
st_clear(st_table *table)
{
    st_free_data(table->as.entries, table->sz);
    table->sz = 0;
    table->num_entries = 0;
    table->as.bins = &fake_bins[1];
    table->free = IDX_NULL;
    table->first = IDX_NULL;
}

void
st_free_table(st_table *table)
{
    st_clear(table);
    st_dealloc_table(table);
}

size_t
st_memsize(const st_table *table)
{
    return sizeof(st_table) + entries_size(table->sz);
}

#ifdef HASH_LOG
static void
count_collision(const struct st_hash_type *type)
{
    collision.all++;
    if (type == &type_numhash) {
	collision.num++;
    }
    else if (type == &type_strhash) {
	collision.strcase++;
    }
    else if (type == &type_strcasehash) {
	collision.str++;
    }
}
#define COLLISION (collision_check ? count_collision(table->type) : (void)0)
#define FOUND_ENTRY (collision_check ? collision.total++ : (void)0)
#else
#define COLLISION
#define FOUND_ENTRY
#endif

#define EQUAL(table,x,ptr) ((x)==(ptr)->key || (*(table)->type->compare)((x),(ptr)->key) == 0)
static inline int
PTR_NOT_EQUAL(const st_table *table, st_idx_t idx, st_idx_t hash_val, st_data_t key)
{
    st_table_entry *ptr = &table->as.entries[idx];
    return idx != IDX_NULL && (ptr->hash != hash_val || !EQUAL(table, key, ptr));
}

#define FIND_ENTRY_GET(table, ptr, key, hash_val) \
    ((ptr) = find_entry((table), (key), (hash_val), hash_pos(hash_val, (table)->sz)))
#define FIND_ENTRY_SET(table, ptr, key, hash_val, bin_pos) \
    ((ptr) = find_entry((table), (key), (hash_val), ((bin_pos) = hash_pos(hash_val, (table)->sz))))

static st_table_entry *
find_entry(const st_table *table, st_data_t key, st_idx_t hash_val,
           st_idx_t bin_pos)
{
    register st_idx_t idx = table->as.bins[Z-bin_pos];
    FOUND_ENTRY;
    if (PTR_NOT_EQUAL(table, idx, hash_val, key)) {
	COLLISION;
	do {
	    idx = table->as.entries[idx].next;
	} while (PTR_NOT_EQUAL(table, idx, hash_val, key));
    }
    if (idx == IDX_NULL)
	return NULL;
    return &table->as.entries[idx];
}

#define collision_check 0

int
st_lookup(st_table *table, register st_data_t key, st_data_t *value)
{
    st_idx_t hash_val;
    register st_table_entry *ptr;

    hash_val = do_hash(key, table);

    FIND_ENTRY_GET(table, ptr, key, hash_val);

    if (ptr == NULL) {
	return 0;
    }
    else {
	if (value != 0) *value = ptr->record;
	return 1;
    }
}

int
st_get_key(st_table *table, register st_data_t key, st_data_t *result)
{
    st_idx_t hash_val;
    register st_table_entry *ptr;

    hash_val = do_hash(key, table);

    FIND_ENTRY_GET(table, ptr, key, hash_val);

    if (ptr == NULL) {
	return 0;
    }
    else {
	if (result != 0)  *result = ptr->key;
	return 1;
    }
}

#undef collision_check
#define collision_check 1

static inline void
add_direct(st_table *table, st_data_t key, st_data_t value,
	   st_idx_t hash_val, register st_idx_t bin_pos)
{
    register st_table_entry *entry;
    st_idx_t en_idx;
    if (table->free == IDX_NULL) {
        rehash(table);
        bin_pos = hash_pos(hash_val, table->sz);
    }

    en_idx = table->free;
    entry = &table->as.entries[en_idx];
    table->free = entry->next;
    entry->next = table->as.bins[Z-bin_pos];
    table->as.bins[Z-bin_pos] = en_idx;
    entry->hash = hash_val;
    entry->key = key;
    entry->record = value;
    entry->forw = IDX_NULL;
    if (table->first != IDX_NULL) {
	entry->prev = table->as.entries[table->first].prev;
	table->as.entries[table->first].prev = en_idx;
	table->as.entries[entry->prev].forw = en_idx;
    } else {
	entry->prev = en_idx;
	table->first = en_idx;
    }
    table->num_entries++;
}

int
st_insert(register st_table *table, register st_data_t key, st_data_t value)
{
    st_idx_t hash_val;
    register st_idx_t bin_pos;
    register st_table_entry *ptr;

    hash_val = do_hash(key, table);

    FIND_ENTRY_SET(table, ptr, key, hash_val, bin_pos);

    if (ptr == NULL) {
	add_direct(table, key, value, hash_val, bin_pos);
	return 0;
    }
    else {
	ptr->record = value;
	return 1;
    }
}

int
st_insert2(register st_table *table, register st_data_t key, st_data_t value,
	   st_data_t (*func)(st_data_t))
{
    st_idx_t hash_val;
    register st_idx_t bin_pos;
    register st_table_entry *ptr;

    hash_val = do_hash(key, table);

    FIND_ENTRY_SET(table, ptr, key, hash_val, bin_pos);

    if (ptr == NULL) {
	key = (*func)(key);
	add_direct(table, key, value, hash_val, bin_pos);
	return 0;
    }
    else {
	ptr->record = value;
	return 1;
    }
}

void
st_add_direct(st_table *table, st_data_t key, st_data_t value)
{
    st_idx_t hash_val;

    hash_val = do_hash(key, table);
    add_direct(table, key, value, hash_val, hash_pos(hash_val, table->sz));
}

static void
rehash(register st_table *table)
{
    st_idx_t i, hash_val;

    if (st_sz[table->sz + 1].nentries == 0) {
#ifndef NOT_RUBY
	rb_raise(rb_eRuntimeError, "hash is too big");
#else
	abort();
#endif
    }
    table->as.entries = st_grow_data(table->as.entries, table->sz+1, table->sz);
    table->sz++;
    table->free = st_sz[table->sz-1].nentries;

    if (st_sz[table->sz].bin_mask != st_sz[table->sz-1].bin_mask) {
	for (i = 0; i < table->free; i++) {
	    hash_val = hash_pos(table->as.entries[i].hash, table->sz);
	    table->as.entries[i].next = table->as.bins[Z-hash_val];
	    table->as.bins[Z-hash_val] = i;
	}
    }
}

st_table*
st_copy(st_table *old_table)
{
    st_table *new_table;

    new_table = st_alloc_table();
    if (new_table == 0) {
	return 0;
    }

    *new_table = *old_table;
    new_table->as.entries = st_alloc_data(new_table->sz);

    if (new_table->as.entries == 0) {
	st_dealloc_table(new_table);
	return 0;
    }

    memcpy(base_ptr(new_table->as.entries, new_table->sz),
            base_ptr(old_table->as.entries, old_table->sz),
            entries_size(new_table->sz));

    return new_table;
}

static inline void
remove_entry(st_table *table, st_idx_t idx)
{
    st_table_entry* en = &table->as.entries[idx];
    if (en->forw != IDX_NULL)
	table->as.entries[en->forw].prev = en->prev;
    else
	table->as.entries[table->first].prev = en->prev;
    if (idx == table->first)
	table->first = en->forw;
    else
	table->as.entries[en->prev].forw = en->forw;
    table->num_entries--;
}

static inline void
free_entry(st_table *table, st_idx_t idx)
{
    table->as.entries[idx].next = table->free;
    table->free = idx;
}

int
st_delete(register st_table *table, register st_data_t *key, st_data_t *value)
{
    st_idx_t hash_val, idx, *prev;
    register st_table_entry *ptr;

    hash_val = do_hash(*key, table);

    prev = &table->as.bins[Z-hash_pos(hash_val, table->sz)];
    for (;(idx = *prev) != IDX_NULL; prev = &ptr->next) {
        ptr = &table->as.entries[idx];
	if (EQUAL(table, *key, ptr)) {
	    *prev = ptr->next;
	    remove_entry(table, idx);
	    if (value != 0) *value = ptr->record;
	    *key = ptr->key;
	    free_entry(table, idx);
	    return 1;
	}
    }

    if (value != 0) *value = 0;
    return 0;
}

int
st_delete_safe(register st_table *table, register st_data_t *key, st_data_t *value, st_data_t never)
{
    st_idx_t hash_val, idx;
    register st_table_entry *ptr;

    hash_val = do_hash(*key, table);

    idx = table->as.bins[Z-hash_pos(hash_val, table->sz)];

    for (; idx != IDX_NULL; idx = ptr->next) {
        ptr = &table->as.entries[idx];
	if ((ptr->key != never) && EQUAL(table, *key, ptr)) {
	    remove_entry(table, idx);
	    *key = ptr->key;
	    if (value != 0) *value = ptr->record;
	    ptr->key = ptr->record = never;
	    ptr->hash = 0;
	    return 1;
	}
    }

    if (value != 0) *value = 0;
    return 0;
}

int
st_shift(register st_table *table, register st_data_t *key, st_data_t *value)
{
    st_table_entry *old;
    st_idx_t *prev;
    st_idx_t idx;

    if (table->num_entries == 0) {
        if (value != 0) *value = 0;
        return 0;
    }

    old = &table->as.entries[table->first];
    prev = &table->as.bins[Z-hash_pos(old->hash, table->sz)];
    while ((idx = *prev) != table->first) prev = &table->as.entries[idx].next;
    *prev = old->next;
    remove_entry(table, table->first);
    if (value != 0) *value = old->record;
    *key = old->key;
    free_entry(table, idx);
    return 1;
}

void
st_cleanup_safe(st_table *table, st_data_t never)
{
    st_table_entry *ptr;
    st_idx_t i, *last, idx, tmp;
    st_idx_t num_bins = st_sz[table->sz].bin_mask + 1;

    for (i = 0; i < num_bins; i++) {
	idx = *(last = &table->as.bins[Z-i]);
	while (idx != IDX_NULL) {
	    ptr = &table->as.entries[idx];
	    if (ptr->key == never) {
		tmp = idx;
		*last = idx = ptr->next;
		free_entry(table, tmp);
	    }
	    else {
		idx = *(last = &ptr->next);
	    }
	}
    }
}

int
st_update(st_table *table, st_data_t key, st_update_callback_func *func, st_data_t arg)
{
    st_idx_t hash_val, bin_pos, *last, idx, tmp;
    register st_table_entry *ptr;
    st_data_t value = 0, old_key;
    int retval, existing = 0;

    hash_val = do_hash(key, table);

    FIND_ENTRY_SET(table, ptr, key, hash_val, bin_pos);
    idx = ptr - table->as.entries;

    if (ptr != NULL) {
	key = ptr->key;
	value = ptr->record;
	existing = 1;
    }
    {
	old_key = key;
	retval = (*func)(&key, &value, arg, existing);
	switch (retval) {
	  case ST_CONTINUE:
	    if (!existing) {
		add_direct(table, key, value, hash_val, hash_pos(hash_val, table->sz));
		break;
	    }
	    if (old_key != key) {
		ptr->key = key;
	    }
	    ptr->record = value;
	    break;
	  case ST_DELETE:
	    if (!existing) break;
	    last = &table->as.bins[Z-bin_pos];
	    for (; (tmp = *last) != IDX_NULL; last = &ptr->next) {
	        ptr = &table->as.entries[tmp];
		if (idx == tmp) {
		    *last = ptr->next;
		    remove_entry(table, tmp);
		    free_entry(table, tmp);
		    break;
		}
	    }
	    break;
	}
	return existing;
    }
}

#define FOR_EACH_BEGIN(table, head, ptr, next) \
    for (head = table->first; head != IDX_NULL; head = next) { \
        ptr = &table->as.entries[head]; \
        next = ptr->forw

#define FOR_EACH_END(table, head, ptr, next) \
    }

int
st_foreach_check(st_table *table, int (*func)(ANYARGS), st_data_t arg, st_data_t never)
{
    st_table_entry *ptr = 0;
    enum st_retval retval;
    st_idx_t idx, head, next, *last;

    if (table->num_entries == 0) {
        return 0;
    }

    FOR_EACH_BEGIN(table, head, ptr, next);
	if (ptr->key != never) {
	    st_idx_t hash = ptr->hash;
	    st_data_t key = ptr->key;
	    retval = (*func)(key, ptr->record, arg, 0);
	    switch (retval) {
	      case ST_CHECK:	/* check if hash is modified during iteration */
		idx = table->as.bins[Z-hash_pos(hash, table->sz)];
		for (; idx != head; idx = ptr->next) {
		    if (idx == IDX_NULL) {
			/* call func with error notice */
			retval = (*func)(0, 0, arg, 1);
			return 1;
		    }
                    ptr = &table->as.entries[idx];
		}
		ptr = &table->as.entries[idx];
		if (ptr->key != key && ptr->key != never) {
		    /* call func with error notice */
		    retval = (*func)(0, 0, arg, 1);
		    return 1;
		}
		/* fall through */
	      case ST_CONTINUE:
		break;
	      case ST_STOP:
		return 0;
	      case ST_DELETE:
		last = &table->as.bins[Z-hash_pos(hash, table->sz)];
		for (; (idx = *last) != IDX_NULL; last = &ptr->next) {
		    ptr = &table->as.entries[idx];
		    if (idx == head) {
			if (ptr->hash == hash && ptr->key == key) {
			    remove_entry(table, idx);
			    ptr->key = ptr->record = never;
			    ptr->hash = 0;
			}
			break;
		    }
		}
		if (table->num_entries == 0) return 0;
	    }
	}
    FOR_EACH_END(table, head, ptr, next);
    return 0;
}

int
st_foreach(st_table *table, int (*func)(ANYARGS), st_data_t arg)
{
    st_table_entry *ptr = 0;
    enum st_retval retval;
    st_idx_t head, next, *last, idx;

    if (table->num_entries == 0) {
        return 0;
    }

    FOR_EACH_BEGIN(table, head, ptr, next);
	retval = (*func)(ptr->key, ptr->record, arg, 0);
	switch (retval) {
	  case ST_CONTINUE:
	    break;
	  case ST_CHECK:
	  case ST_STOP:
	    return 0;
	  case ST_DELETE:
	    last = &table->as.bins[Z-hash_pos(ptr->hash, table->sz)];
	    for (; (idx = *last) != IDX_NULL; last = &ptr->next) {
		ptr = &table->as.entries[idx];
		if (idx == head) {
		    *last = ptr->next;
		    remove_entry(table, idx);
		    free_entry(table, idx);
		    break;
		}
	    }
	    if (table->num_entries == 0) return 0;
	}
    FOR_EACH_END(table, head, ptr, next);
    return 0;
}

static st_index_t
get_keys(const st_table *table, st_data_t *keys, st_index_t size,
         int check, st_data_t never)
{
    st_data_t key;
    st_data_t *keys_start = keys;

    st_table_entry *ptr = 0;
    st_data_t *keys_end = keys + size;
    
    st_idx_t idx = table->first;

    while (idx != IDX_NULL) {
        ptr = &table->as.entries[idx];
        if (keys >= keys_end) break;
        key = ptr->key;
        if (check && key == never) continue;
        *keys++ = key;
        idx = ptr->forw;
    }

    return keys - keys_start;
}

st_index_t
st_keys(st_table *table, st_data_t *keys, st_index_t size)
{
    return get_keys(table, keys, size, 0, 0);
}

st_index_t
st_keys_check(st_table *table, st_data_t *keys, st_index_t size, st_data_t never)
{
    return get_keys(table, keys, size, 1, never);
}

static st_index_t
get_values(const st_table *table, st_data_t *values, st_index_t size,
           int check, st_data_t never)
{
    st_data_t key;
    st_data_t *values_start = values;

    st_table_entry *ptr = 0;
    st_data_t *values_end = values + size;

    st_idx_t idx = table->first;

    while (idx != IDX_NULL) {
        ptr = &table->as.entries[idx];
        if (values >= values_end) break;
        key = ptr->key;
        if (check && key == never) continue;
        *values++ = ptr->record;
        idx = ptr->forw;
    }

    return values - values_start;
}

st_index_t
st_values(st_table *table, st_data_t *values, st_index_t size)
{
    return get_values(table, values, size, 0, 0);
}

st_index_t
st_values_check(st_table *table, st_data_t *values, st_index_t size, st_data_t never)
{
    return get_values(table, values, size, 1, never);
}

/*
 * hash_32 - 32 bit Fowler/Noll/Vo FNV-1a hash code
 *
 * @(#) $Hash32: Revision: 1.1 $
 * @(#) $Hash32: Id: hash_32a.c,v 1.1 2003/10/03 20:38:53 chongo Exp $
 * @(#) $Hash32: Source: /usr/local/src/cmd/fnv/RCS/hash_32a.c,v $
 *
 ***
 *
 * Fowler/Noll/Vo hash
 *
 * The basis of this hash algorithm was taken from an idea sent
 * as reviewer comments to the IEEE POSIX P1003.2 committee by:
 *
 *      Phong Vo (http://www.research.att.com/info/kpv/)
 *      Glenn Fowler (http://www.research.att.com/~gsf/)
 *
 * In a subsequent ballot round:
 *
 *      Landon Curt Noll (http://www.isthe.com/chongo/)
 *
 * improved on their algorithm.  Some people tried this hash
 * and found that it worked rather well.  In an EMail message
 * to Landon, they named it the ``Fowler/Noll/Vo'' or FNV hash.
 *
 * FNV hashes are designed to be fast while maintaining a low
 * collision rate. The FNV speed allows one to quickly hash lots
 * of data while maintaining a reasonable collision rate.  See:
 *
 *      http://www.isthe.com/chongo/tech/comp/fnv/index.html
 *
 * for more details as well as other forms of the FNV hash.
 ***
 *
 * To use the recommended 32 bit FNV-1a hash, pass FNV1_32A_INIT as the
 * Fnv32_t hashval argument to fnv_32a_buf() or fnv_32a_str().
 *
 ***
 *
 * Please do not copyright this code.  This code is in the public domain.
 *
 * LANDON CURT NOLL DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO
 * EVENT SHALL LANDON CURT NOLL BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * By:
 *	chongo <Landon Curt Noll> /\oo/\
 *      http://www.isthe.com/chongo/
 *
 * Share and Enjoy!	:-)
 */

/*
 * 32 bit FNV-1 and FNV-1a non-zero initial basis
 *
 * The FNV-1 initial basis is the FNV-0 hash of the following 32 octets:
 *
 *              chongo <Landon Curt Noll> /\../\
 *
 * NOTE: The \'s above are not back-slashing escape characters.
 * They are literal ASCII  backslash 0x5c characters.
 *
 * NOTE: The FNV-1a initial basis is the same value as FNV-1 by definition.
 */
#define FNV1_32A_INIT 0x811c9dc5

/*
 * 32 bit magic FNV-1a prime
 */
#define FNV_32_PRIME 0x01000193

#ifdef ST_USE_FNV1
static st_index_t
strhash(st_data_t arg)
{
    register const char *string = (const char *)arg;
    register st_index_t hval = FNV1_32A_INIT;

    /*
     * FNV-1a hash each octet in the buffer
     */
    while (*string) {
	/* xor the bottom with the current octet */
	hval ^= (unsigned int)*string++;

	/* multiply by the 32 bit FNV magic prime mod 2^32 */
	hval *= FNV_32_PRIME;
    }
    return hval;
}
#else

#if !defined(UNALIGNED_WORD_ACCESS) && defined(__GNUC__) && __GNUC__ >= 6
# define UNALIGNED_WORD_ACCESS 0
#endif

#ifndef UNALIGNED_WORD_ACCESS
# if defined(__i386) || defined(__i386__) || defined(_M_IX86) || \
     defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || \
     defined(__powerpc64__) || \
     defined(__mc68020__)
#   define UNALIGNED_WORD_ACCESS 1
# endif
#endif
#ifndef UNALIGNED_WORD_ACCESS
# define UNALIGNED_WORD_ACCESS 0
#endif

/* MurmurHash described in http://murmurhash.googlepages.com/ */
#ifndef MURMUR
#define MURMUR 2
#endif

#define MurmurMagic_1 (st_index_t)0xc6a4a793
#define MurmurMagic_2 (st_index_t)0x5bd1e995
#if MURMUR == 1
#define MurmurMagic MurmurMagic_1
#elif MURMUR == 2
#if SIZEOF_ST_INDEX_T > 4
#define MurmurMagic ((MurmurMagic_1 << 32) | MurmurMagic_2)
#else
#define MurmurMagic MurmurMagic_2
#endif
#endif

static inline st_index_t
murmur(st_index_t h, st_index_t k, int r)
{
    const st_index_t m = MurmurMagic;
#if MURMUR == 1
    h += k;
    h *= m;
    h ^= h >> r;
#elif MURMUR == 2
    k *= m;
    k ^= k >> r;
    k *= m;

    h *= m;
    h ^= k;
#endif
    return h;
}

static inline st_index_t
murmur_finish(st_index_t h)
{
#if MURMUR == 1
    h = murmur(h, 0, 10);
    h = murmur(h, 0, 17);
#elif MURMUR == 2
    h ^= h >> 13;
    h *= MurmurMagic;
    h ^= h >> 15;
#endif
    return h;
}

#define murmur_step(h, k) murmur((h), (k), 16)

#if MURMUR == 1
#define murmur1(h) murmur_step((h), 16)
#else
#define murmur1(h) murmur_step((h), 24)
#endif

st_index_t
st_hash(const void *ptr, size_t len, st_index_t h)
{
    const char *data = ptr;
    st_index_t t = 0;

    h += 0xdeadbeef;

#define data_at(n) (st_index_t)((unsigned char)data[(n)])
#define UNALIGNED_ADD_4 UNALIGNED_ADD(2); UNALIGNED_ADD(1); UNALIGNED_ADD(0)
#if SIZEOF_ST_INDEX_T > 4
#define UNALIGNED_ADD_8 UNALIGNED_ADD(6); UNALIGNED_ADD(5); UNALIGNED_ADD(4); UNALIGNED_ADD(3); UNALIGNED_ADD_4
#if SIZEOF_ST_INDEX_T > 8
#define UNALIGNED_ADD_16 UNALIGNED_ADD(14); UNALIGNED_ADD(13); UNALIGNED_ADD(12); UNALIGNED_ADD(11); \
    UNALIGNED_ADD(10); UNALIGNED_ADD(9); UNALIGNED_ADD(8); UNALIGNED_ADD(7); UNALIGNED_ADD_8
#define UNALIGNED_ADD_ALL UNALIGNED_ADD_16
#endif
#define UNALIGNED_ADD_ALL UNALIGNED_ADD_8
#else
#define UNALIGNED_ADD_ALL UNALIGNED_ADD_4
#endif
    if (len >= sizeof(st_index_t)) {
#if !UNALIGNED_WORD_ACCESS
	int align = (int)((st_data_t)data % sizeof(st_index_t));
	if (align) {
	    st_index_t d = 0;
	    int sl, sr, pack;

	    switch (align) {
#ifdef WORDS_BIGENDIAN
# define UNALIGNED_ADD(n) case SIZEOF_ST_INDEX_T - (n) - 1: \
		t |= data_at(n) << CHAR_BIT*(SIZEOF_ST_INDEX_T - (n) - 2)
#else
# define UNALIGNED_ADD(n) case SIZEOF_ST_INDEX_T - (n) - 1:	\
		t |= data_at(n) << CHAR_BIT*(n)
#endif
		UNALIGNED_ADD_ALL;
#undef UNALIGNED_ADD
	    }

#ifdef WORDS_BIGENDIAN
	    t >>= (CHAR_BIT * align) - CHAR_BIT;
#else
	    t <<= (CHAR_BIT * align);
#endif

	    data += sizeof(st_index_t)-align;
	    len -= sizeof(st_index_t)-align;

	    sl = CHAR_BIT * (SIZEOF_ST_INDEX_T-align);
	    sr = CHAR_BIT * align;

	    while (len >= sizeof(st_index_t)) {
		d = *(st_index_t *)data;
#ifdef WORDS_BIGENDIAN
		t = (t << sr) | (d >> sl);
#else
		t = (t >> sr) | (d << sl);
#endif
		h = murmur_step(h, t);
		t = d;
		data += sizeof(st_index_t);
		len -= sizeof(st_index_t);
	    }

	    pack = len < (size_t)align ? (int)len : align;
	    d = 0;
	    switch (pack) {
#ifdef WORDS_BIGENDIAN
# define UNALIGNED_ADD(n) case (n) + 1: \
		d |= data_at(n) << CHAR_BIT*(SIZEOF_ST_INDEX_T - (n) - 1)
#else
# define UNALIGNED_ADD(n) case (n) + 1: \
		d |= data_at(n) << CHAR_BIT*(n)
#endif
		UNALIGNED_ADD_ALL;
#undef UNALIGNED_ADD
	    }
#ifdef WORDS_BIGENDIAN
	    t = (t << sr) | (d >> sl);
#else
	    t = (t >> sr) | (d << sl);
#endif

#if MURMUR == 2
	    if (len < (size_t)align) goto skip_tail;
#endif
	    h = murmur_step(h, t);
	    data += pack;
	    len -= pack;
	}
	else
#endif
	{
	    do {
		h = murmur_step(h, *(st_index_t *)data);
		data += sizeof(st_index_t);
		len -= sizeof(st_index_t);
	    } while (len >= sizeof(st_index_t));
	}
    }

    t = 0;
    switch (len) {
#ifdef WORDS_BIGENDIAN
# define UNALIGNED_ADD(n) case (n) + 1: \
	t |= data_at(n) << CHAR_BIT*(SIZEOF_ST_INDEX_T - (n) - 1)
#else
# define UNALIGNED_ADD(n) case (n) + 1: \
	t |= data_at(n) << CHAR_BIT*(n)
#endif
	UNALIGNED_ADD_ALL;
#undef UNALIGNED_ADD
#if MURMUR == 1
	h = murmur_step(h, t);
#elif MURMUR == 2
# if !UNALIGNED_WORD_ACCESS
      skip_tail:
# endif
	h ^= t;
	h *= MurmurMagic;
#endif
    }

    return murmur_finish(h);
}

st_index_t
st_hash_uint32(st_index_t h, uint32_t i)
{
    return murmur_step(h + i, 16);
}

st_index_t
st_hash_uint(st_index_t h, st_index_t i)
{
    st_index_t v = 0;
    h += i;
#ifdef WORDS_BIGENDIAN
#if SIZEOF_ST_INDEX_T*CHAR_BIT > 12*8
    v = murmur1(v + (h >> 12*8));
#endif
#if SIZEOF_ST_INDEX_T*CHAR_BIT > 8*8
    v = murmur1(v + (h >> 8*8));
#endif
#if SIZEOF_ST_INDEX_T*CHAR_BIT > 4*8
    v = murmur1(v + (h >> 4*8));
#endif
#endif
    v = murmur1(v + h);
#ifndef WORDS_BIGENDIAN
#if SIZEOF_ST_INDEX_T*CHAR_BIT > 4*8
    v = murmur1(v + (h >> 4*8));
#endif
#if SIZEOF_ST_INDEX_T*CHAR_BIT > 8*8
    v = murmur1(v + (h >> 8*8));
#endif
#if SIZEOF_ST_INDEX_T*CHAR_BIT > 12*8
    v = murmur1(v + (h >> 12*8));
#endif
#endif
    return v;
}

st_index_t
st_hash_end(st_index_t h)
{
    h = murmur_step(h, 10);
    h = murmur_step(h, 17);
    return h;
}

#undef st_hash_start
st_index_t
st_hash_start(st_index_t h)
{
    return h;
}

static st_index_t
strhash(st_data_t arg)
{
    register const char *string = (const char *)arg;
    return st_hash(string, strlen(string), FNV1_32A_INIT);
}
#endif

int
st_locale_insensitive_strcasecmp(const char *s1, const char *s2)
{
    unsigned int c1, c2;

    while (1) {
        c1 = (unsigned char)*s1++;
        c2 = (unsigned char)*s2++;
        if (c1 == '\0' || c2 == '\0') {
            if (c1 != '\0') return 1;
            if (c2 != '\0') return -1;
            return 0;
        }
        if ((unsigned int)(c1 - 'A') <= ('Z' - 'A')) c1 += 'a' - 'A';
        if ((unsigned int)(c2 - 'A') <= ('Z' - 'A')) c2 += 'a' - 'A';
        if (c1 != c2) {
            if (c1 > c2)
                return 1;
            else
                return -1;
        }
    }
}

int
st_locale_insensitive_strncasecmp(const char *s1, const char *s2, size_t n)
{
    unsigned int c1, c2;

    while (n--) {
        c1 = (unsigned char)*s1++;
        c2 = (unsigned char)*s2++;
        if (c1 == '\0' || c2 == '\0') {
            if (c1 != '\0') return 1;
            if (c2 != '\0') return -1;
            return 0;
        }
        if ((unsigned int)(c1 - 'A') <= ('Z' - 'A')) c1 += 'a' - 'A';
        if ((unsigned int)(c2 - 'A') <= ('Z' - 'A')) c2 += 'a' - 'A';
        if (c1 != c2) {
            if (c1 > c2)
                return 1;
            else
                return -1;
        }
    }
    return 0;
}

static st_index_t
strcasehash(st_data_t arg)
{
    register const char *string = (const char *)arg;
    register st_index_t hval = FNV1_32A_INIT;

    /*
     * FNV-1a hash each octet in the buffer
     */
    while (*string) {
	unsigned int c = (unsigned char)*string++;
	if ((unsigned int)(c - 'A') <= ('Z' - 'A')) c += 'a' - 'A';
	hval ^= c;

	/* multiply by the 32 bit FNV magic prime mod 2^32 */
	hval *= FNV_32_PRIME;
    }
    return hval;
}

int
st_numcmp(st_data_t x, st_data_t y)
{
    return x != y;
}

st_index_t
st_numhash(st_data_t n)
{
#if SIZEOF_ST_INDEX_T > 4
    n ^= n >> 12;
    n ^= n << 25;
    return (st_index_t)(n ^ (n >> 27));
#else
    enum {s1 = 11, s2 = 3};
    return (st_index_t)(((n>>s1)^(n<<s2)) ^ (n>>s2));
#endif
}
