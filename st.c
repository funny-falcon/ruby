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
    st_index_t hash;
    st_data_t key;
    st_data_t record;
    st_table_entry *next;
    struct list_node olist;
};

typedef struct st_packed_entry {
    st_index_t hash;
    st_data_t key, val;
} st_packed_entry;

#ifndef STATIC_ASSERT
#define STATIC_ASSERT(name, expr) typedef int static_assert_##name##_check[(expr) ? 1 : -1]
#endif

#define ST_DEFAULT_MAX_DENSITY 5
#define ST_DEFAULT_INIT_TABLE_SIZE 16
#define ST_DEFAULT_PACKED_TABLE_SIZE 18
#define PACKED_UNIT (int)(sizeof(st_packed_entry) / sizeof(st_table_entry*))
#define MAX_PACKED_HASH (int)(ST_DEFAULT_PACKED_TABLE_SIZE * sizeof(st_table_entry*) / sizeof(st_packed_entry))

STATIC_ASSERT(st_packed_entry, sizeof(st_packed_entry) == sizeof(st_table_entry*[PACKED_UNIT]));
STATIC_ASSERT(st_packed_bins, sizeof(st_packed_entry[MAX_PACKED_HASH]) <= sizeof(st_table_entry*[ST_DEFAULT_PACKED_TABLE_SIZE]));

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
#undef malloc
#undef realloc
#undef calloc
#undef free
#define malloc xmalloc
#define calloc xcalloc
#define realloc xrealloc
#define free(x) xfree(x)
#endif

#define EQUAL(table,x,ent) ((x)==(ent)->key || (*(table)->type->compare)((x),(ent)->key) == 0)

#define do_hash(key,table) (st_index_t)(*(table)->type->hash)((key))
#define hash_pos(h,n) ((h) & (n - 1))

/* preparation for possible allocation improvements */
#define st_alloc_entry() (st_table_entry *)malloc(sizeof(st_table_entry))
#define st_free_entry(entry) free(entry)
#define st_alloc_table() (st_table *)malloc(sizeof(st_table))
#define st_dealloc_table(table) free(table)
#define st_alloc_bins(size) (st_table_entry **)calloc(size, sizeof(st_table_entry *))
#define st_free_bins(bins, size) free(bins)
static inline st_table_entry**
st_realloc_bins(st_table_entry **bins, st_index_t newsize, st_index_t oldsize)
{
    bins = (st_table_entry **)realloc(bins, newsize * sizeof(st_table_entry *));
    MEMZERO(bins, st_table_entry*, newsize);
    return bins;
}

/* Shortcut */
#define bins as.big.bins
#define real_entries as.packed.real_entries

/* preparation for possible packing improvements */
#define PACKED_BINS(table) ((table)->as.packed.entries)
#define PACKED_ENT(table, i) PACKED_BINS(table)[i]
#define PKEY(table, i) PACKED_ENT((table), (i)).key
#define PVAL(table, i) PACKED_ENT((table), (i)).val
#define PHASH(table, i) PACKED_ENT((table), (i)).hash
#define PKEY_SET(table, i, v) (PKEY((table), (i)) = (v))
#define PVAL_SET(table, i, v) (PVAL((table), (i)) = (v))
#define PHASH_SET(table, i, v) (PHASH((table), (i)) = (v))

/* this function depends much on packed layout, so that it placed here */
static inline void
remove_packed_entry(st_table *table, st_index_t i)
{
    table->real_entries--;
    table->num_entries--;
    if (i < table->real_entries) {
	MEMMOVE(&PACKED_ENT(table, i), &PACKED_ENT(table, i+1),
		st_packed_entry, table->real_entries - i);
    }
}

static inline void
remove_safe_packed_entry(st_table *table, st_index_t i, st_data_t never)
{
    table->num_entries--;
    PKEY_SET(table, i, never);
    PVAL_SET(table, i, never);
    PHASH_SET(table, i, 0);
}

static st_index_t
next_pow2(st_index_t x)
{
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
#if SIZEOF_ST_INDEX_T == 8
    x |= x >> 32;
#endif
    return x + 1;
}

static st_index_t
new_size(st_index_t size)
{
    st_index_t n;

    if (size && (size & ~(size - 1)) == size) /* already a power-of-two? */
	return size;

    n = next_pow2(size);
    if (n > size)
	return n;
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
    FILE *f;
    if (!collision.total) return;
    f = fopen((snprintf(fname, sizeof(fname), "/tmp/col%ld", (long)getpid()), fname), "w");
    fprintf(f, "collision: %d / %d (%6.2f)\n", collision.all, collision.total,
	    ((double)collision.all / (collision.total)) * 100);
    fprintf(f, "num: %d, str: %d, strcase: %d\n", collision.num, collision.str, collision.strcase);
    fclose(f);
}
#endif

static struct list_head *
st_head(const st_table *tbl)
{
    uintptr_t addr = (uintptr_t)&tbl->as.big.private_list_head;
    return (struct list_head *)addr;
}

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
    tbl->entries_packed = size <= MAX_PACKED_HASH;
    if (tbl->entries_packed) {
	size = ST_DEFAULT_PACKED_TABLE_SIZE;
	tbl->real_entries = 0;
    }
    else {
	size = new_size(size);	/* round up to power-of-two */
	list_head_init(st_head(tbl));
    }
    tbl->num_bins = size;
    tbl->bins = st_alloc_bins(size);

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
    register st_table_entry *ptr = 0, *next;

    if (table->entries_packed) {
        table->num_entries = 0;
        table->real_entries = 0;
        return;
    }

    list_for_each_safe(st_head(table), ptr, next, olist) {
	/* list_del is not needed */
	st_free_entry(ptr);
    }
    table->num_entries = 0;
    MEMZERO(table->bins, st_table_entry*, table->num_bins);
    list_head_init(st_head(table));
}

void
st_free_table(st_table *table)
{
    st_clear(table);
    st_free_bins(table->bins, table->num_bins);
    st_dealloc_table(table);
}

size_t
st_memsize(const st_table *table)
{
    if (table->entries_packed) {
	return table->num_bins * sizeof (void *) + sizeof(st_table);
    }
    else {
	return table->num_entries * sizeof(struct st_table_entry) + table->num_bins * sizeof (void *) + sizeof(st_table);
    }
}

#define PTR_NOT_EQUAL(table, ptr, hash_val, key) \
((ptr) != 0 && ((ptr)->hash != (hash_val) || !EQUAL((table), (key), (ptr))))

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
#define collision_check 0
#else
#define COLLISION
#define FOUND_ENTRY
#endif

#define FIND_ENTRY(table, ptr, hash_val, bin_pos) \
    ((ptr) = find_entry((table), key, (hash_val), ((bin_pos) = hash_pos(hash_val, (table)->num_bins))))

static st_table_entry *
find_entry(const st_table *table, st_data_t key, st_index_t hash_val,
           st_index_t bin_pos)
{
    register st_table_entry *ptr = table->bins[bin_pos];
    FOUND_ENTRY;
    if (PTR_NOT_EQUAL(table, ptr, hash_val, key)) {
	COLLISION;
	while (PTR_NOT_EQUAL(table, ptr->next, hash_val, key)) {
	    ptr = ptr->next;
	}
	ptr = ptr->next;
    }
    return ptr;
}

static inline st_index_t
find_packed_index_from(const st_table *table, st_index_t hash_val,
		       st_data_t key, st_index_t i)
{
    while (i < table->real_entries &&
	   (PHASH(table, i) != hash_val || !EQUAL(table, key, &PACKED_ENT(table, i)))) {
	i++;
    }
    return i;
}

static inline st_index_t
find_packed_index(const st_table *table, st_index_t hash_val, st_data_t key)
{
    return find_packed_index_from(table, hash_val, key, 0);
}

int
st_lookup(st_table *table, register st_data_t key, st_data_t *value)
{
    st_index_t hash_val;
    register st_table_entry *ptr;

    hash_val = do_hash(key, table);

    if (table->entries_packed) {
	st_index_t i = find_packed_index(table, hash_val, key);
	if (i < table->real_entries) {
	    if (value != 0) *value = PVAL(table, i);
	    return 1;
	}
        return 0;
    }

    ptr = find_entry(table, key, hash_val, hash_pos(hash_val, table->num_bins));

    if (ptr == 0) {
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
    st_index_t hash_val;
    register st_table_entry *ptr;

    hash_val = do_hash(key, table);

    if (table->entries_packed) {
	st_index_t i = find_packed_index(table, hash_val, key);
	if (i < table->real_entries) {
	    if (result != 0) *result = PKEY(table, i);
	    return 1;
	}
        return 0;
    }

    ptr = find_entry(table, key, hash_val, hash_pos(hash_val, table->num_bins));

    if (ptr == 0) {
	return 0;
    }
    else {
	if (result != 0)  *result = ptr->key;
	return 1;
    }
}

static inline st_table_entry *
new_entry(st_table * table, st_data_t key, st_data_t value,
	st_index_t hash_val, register st_index_t bin_pos)
{
    register st_table_entry *entry = st_alloc_entry();

    entry->next = table->bins[bin_pos];
    table->bins[bin_pos] = entry;
    entry->hash = hash_val;
    entry->key = key;
    entry->record = value;

    return entry;
}

static inline void
add_direct(st_table *table, st_data_t key, st_data_t value,
	   st_index_t hash_val, register st_index_t bin_pos)
{
    register st_table_entry *entry;
    if (table->num_entries > ST_DEFAULT_MAX_DENSITY * table->num_bins) {
	rehash(table);
        bin_pos = hash_pos(hash_val, table->num_bins);
    }

    entry = new_entry(table, key, value, hash_val, bin_pos);
    list_add_tail(st_head(table), &entry->olist);
    table->num_entries++;
}

static void
unpack_entries(register st_table *table)
{
    st_index_t i;
    st_packed_entry packed_bins[MAX_PACKED_HASH];
    register st_table_entry *entry;
    st_table tmp_table = *table;

    MEMCPY(packed_bins, PACKED_BINS(table), st_packed_entry, MAX_PACKED_HASH);
    table->as.packed.entries = packed_bins;
    tmp_table.entries_packed = 0;
#if ST_DEFAULT_INIT_TABLE_SIZE == ST_DEFAULT_PACKED_TABLE_SIZE
    MEMZERO(tmp_table.bins, st_table_entry*, tmp_table.num_bins);
#else
    tmp_table.bins = st_realloc_bins(tmp_table.bins, ST_DEFAULT_INIT_TABLE_SIZE, tmp_table.num_bins);
    tmp_table.num_bins = ST_DEFAULT_INIT_TABLE_SIZE;
#endif

    /*
     * order is important here, we need to keep the original table
     * walkable during GC (GC may be triggered by new_entry call)
     */
    i = 0;
    list_head_init(st_head(&tmp_table));
    do {
	st_data_t key = packed_bins[i].key;
	st_data_t val = packed_bins[i].val;
	st_index_t hash = packed_bins[i].hash;
	entry = new_entry(&tmp_table, key, val, hash,
			  hash_pos(hash, ST_DEFAULT_INIT_TABLE_SIZE));
	list_add_tail(st_head(&tmp_table), &entry->olist);
    } while (++i < MAX_PACKED_HASH);
    *table = tmp_table;
    list_head_init(st_head(table));
    list_append_list(st_head(table), st_head(&tmp_table));
}

static void
add_packed_direct(st_table *table, st_data_t key, st_data_t value, st_index_t hash_val)
{
    if (table->real_entries < MAX_PACKED_HASH) {
	st_index_t i = table->real_entries++;
	PKEY_SET(table, i, key);
	PVAL_SET(table, i, value);
	PHASH_SET(table, i, hash_val);
	table->num_entries++;
    }
    else {
	unpack_entries(table);
	add_direct(table, key, value, hash_val, hash_pos(hash_val, table->num_bins));
    }
}


int
st_insert(register st_table *table, register st_data_t key, st_data_t value)
{
    st_index_t hash_val;
    register st_index_t bin_pos;
    register st_table_entry *ptr;

    hash_val = do_hash(key, table);

    if (table->entries_packed) {
	st_index_t i = find_packed_index(table, hash_val, key);
	if (i < table->real_entries) {
	    PVAL_SET(table, i, value);
	    return 1;
        }
	add_packed_direct(table, key, value, hash_val);
	return 0;
    }

    FIND_ENTRY(table, ptr, hash_val, bin_pos);

    if (ptr == 0) {
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
    st_index_t hash_val;
    register st_index_t bin_pos;
    register st_table_entry *ptr;

    hash_val = do_hash(key, table);

    if (table->entries_packed) {
	st_index_t i = find_packed_index(table, hash_val, key);
	if (i < table->real_entries) {
	    PVAL_SET(table, i, value);
	    return 1;
	}
	key = (*func)(key);
	add_packed_direct(table, key, value, hash_val);
	return 0;
    }

    FIND_ENTRY(table, ptr, hash_val, bin_pos);

    if (ptr == 0) {
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
    st_index_t hash_val;

    hash_val = do_hash(key, table);
    if (table->entries_packed) {
	add_packed_direct(table, key, value, hash_val);
	return;
    }

    add_direct(table, key, value, hash_val, hash_pos(hash_val, table->num_bins));
}

static void
rehash(register st_table *table)
{
    register st_table_entry *ptr = 0, **new_bins;
    st_index_t new_num_bins, hash_val;

    new_num_bins = new_size(table->num_bins+1);
    new_bins = st_realloc_bins(table->bins, new_num_bins, table->num_bins);
    table->num_bins = new_num_bins;
    table->bins = new_bins;

    list_for_each(st_head(table), ptr, olist) {
	hash_val = hash_pos(ptr->hash, new_num_bins);
	ptr->next = new_bins[hash_val];
	new_bins[hash_val] = ptr;
    }
}

st_table*
st_copy(st_table *old_table)
{
    st_table *new_table;
    st_table_entry *ptr = 0, *entry;
    st_index_t num_bins = old_table->num_bins;

    new_table = st_alloc_table();
    if (new_table == 0) {
	return 0;
    }

    *new_table = *old_table;
    new_table->bins = st_alloc_bins(num_bins);

    if (new_table->bins == 0) {
	st_dealloc_table(new_table);
	return 0;
    }

    if (old_table->entries_packed) {
        MEMCPY(new_table->bins, old_table->bins, st_table_entry*, old_table->num_bins);
        return new_table;
    }

    list_head_init(st_head(new_table));

    list_for_each(st_head(old_table), ptr, olist) {
	entry = new_entry(new_table, ptr->key, ptr->record, ptr->hash,
			    hash_pos(ptr->hash, num_bins));
	list_add_tail(st_head(new_table), &entry->olist);
    }

    return new_table;
}

static inline void
remove_entry(st_table *table, st_table_entry *ptr)
{
    list_del(&ptr->olist);
    table->num_entries--;
}

int
st_delete(register st_table *table, register st_data_t *key, st_data_t *value)
{
    st_index_t hash_val;
    st_table_entry **prev;
    register st_table_entry *ptr;

    hash_val = do_hash(*key, table);

    if (table->entries_packed) {
	st_index_t i = find_packed_index(table, hash_val, *key);
	if (i < table->real_entries) {
	    if (value != 0) *value = PVAL(table, i);
	    *key = PKEY(table, i);
	    remove_packed_entry(table, i);
	    return 1;
        }
        if (value != 0) *value = 0;
        return 0;
    }

    prev = &table->bins[hash_pos(hash_val, table->num_bins)];
    for (;(ptr = *prev) != 0; prev = &ptr->next) {
	if (EQUAL(table, *key, ptr)) {
	    *prev = ptr->next;
	    remove_entry(table, ptr);
	    if (value != 0) *value = ptr->record;
	    *key = ptr->key;
	    st_free_entry(ptr);
	    return 1;
	}
    }

    if (value != 0) *value = 0;
    return 0;
}

int
st_delete_safe(register st_table *table, register st_data_t *key, st_data_t *value, st_data_t never)
{
    st_index_t hash_val;
    register st_table_entry *ptr;

    hash_val = do_hash(*key, table);

    if (table->entries_packed) {
	st_index_t i = find_packed_index(table, hash_val, *key);
	if (i < table->real_entries) {
	    if (value != 0) *value = PVAL(table, i);
	    *key = PKEY(table, i);
	    remove_safe_packed_entry(table, i, never);
	    return 1;
	}
	if (value != 0) *value = 0;
	return 0;
    }

    ptr = table->bins[hash_pos(hash_val, table->num_bins)];

    for (; ptr != 0; ptr = ptr->next) {
	if ((ptr->key != never) && EQUAL(table, *key, ptr)) {
	    remove_entry(table, ptr);
	    *key = ptr->key;
	    if (value != 0) *value = ptr->record;
	    ptr->key = ptr->record = never;
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
    st_table_entry **prev;
    register st_table_entry *ptr;

    if (table->num_entries == 0) {
        if (value != 0) *value = 0;
        return 0;
    }

    if (table->entries_packed) {
        if (value != 0) *value = PVAL(table, 0);
        *key = PKEY(table, 0);
        remove_packed_entry(table, 0);
        return 1;
    }

    old = list_pop(st_head(table), st_table_entry, olist);
    table->num_entries--;
    prev = &table->bins[hash_pos(old->hash, table->num_bins)];
    while ((ptr = *prev) != old) prev = &ptr->next;
    *prev = ptr->next;
    if (value != 0) *value = ptr->record;
    *key = ptr->key;
    st_free_entry(ptr);
    return 1;
}

void
st_cleanup_safe(st_table *table, st_data_t never)
{
    st_table_entry *ptr, **last, *tmp;
    st_index_t i;

    if (table->entries_packed) {
	st_index_t i = 0, j = 0;
	while (PKEY(table, i) != never) {
	    if (i++ == table->real_entries) return;
	}
	for (j = i; ++i < table->real_entries;) {
	    if (PKEY(table, i) == never) continue;
	    PACKED_ENT(table, j) = PACKED_ENT(table, i);
	    j++;
	}
	table->real_entries = j;
	/* table->num_entries really should be equal j at this moment, but let set it anyway */
	table->num_entries = j;
	return;
    }

    for (i = 0; i < table->num_bins; i++) {
	ptr = *(last = &table->bins[i]);
	while (ptr != 0) {
	    if (ptr->key == never) {
		tmp = ptr;
		*last = ptr = ptr->next;
		st_free_entry(tmp);
	    }
	    else {
		ptr = *(last = &ptr->next);
	    }
	}
    }
}

int
st_update(st_table *table, st_data_t key, st_update_callback_func *func, st_data_t arg)
{
    st_index_t hash_val, bin_pos;
    register st_table_entry *ptr, **last, *tmp;
    st_data_t value = 0, old_key;
    int retval, existing = 0;

    hash_val = do_hash(key, table);

    if (table->entries_packed) {
	st_index_t i = find_packed_index(table, hash_val, key);
	if (i < table->real_entries) {
	    key = PKEY(table, i);
	    value = PVAL(table, i);
	    existing = 1;
	}
	{
	    old_key = key;
	    retval = (*func)(&key, &value, arg, existing);
	    if (!table->entries_packed) {
		FIND_ENTRY(table, ptr, hash_val, bin_pos);
		goto unpacked;
	    }
	    switch (retval) {
	      case ST_CONTINUE:
		if (!existing) {
		    add_packed_direct(table, key, value, hash_val);
		    break;
		}
		if (old_key != key) {
		    PKEY(table, i) = key;
		}
		PVAL_SET(table, i, value);
		break;
	      case ST_DELETE:
		if (!existing) break;
		remove_packed_entry(table, i);
	    }
	}
	return existing;
    }

    FIND_ENTRY(table, ptr, hash_val, bin_pos);

    if (ptr != 0) {
	key = ptr->key;
	value = ptr->record;
	existing = 1;
    }
    {
	old_key = key;
	retval = (*func)(&key, &value, arg, existing);
      unpacked:
	switch (retval) {
	  case ST_CONTINUE:
	    if (!existing) {
		add_direct(table, key, value, hash_val, hash_pos(hash_val, table->num_bins));
		break;
	    }
	    if (old_key != key) {
		ptr->key = key;
	    }
	    ptr->record = value;
	    break;
	  case ST_DELETE:
	    if (!existing) break;
	    last = &table->bins[bin_pos];
	    for (; (tmp = *last) != 0; last = &tmp->next) {
		if (ptr == tmp) {
		    *last = ptr->next;
		    remove_entry(table, ptr);
		    st_free_entry(ptr);
		    break;
		}
	    }
	    break;
	}
	return existing;
    }
}

int
st_foreach_check(st_table *table, int (*func)(ANYARGS), st_data_t arg, st_data_t never)
{
    st_table_entry *ptr = 0, **last, *tmp, *next;
    struct list_head *head;
    enum st_retval retval;
    st_index_t i;

    if (table->entries_packed) {
	for (i = 0; i < table->real_entries; i++) {
	    st_data_t key, val;
	    st_index_t hash;
	    key = PKEY(table, i);
	    val = PVAL(table, i);
	    hash = PHASH(table, i);
	    if (key == never) continue;
	    retval = (*func)(key, val, arg, 0);
	    if (!table->entries_packed) {
		FIND_ENTRY(table, ptr, hash, i);
		if (retval == ST_CHECK) {
		    if (!ptr) goto deleted;
		}
		if (table->num_entries == 0) return 0;
		head = st_head(table);
		next = list_entry(ptr->olist.next, st_table_entry, olist);
		goto unpacked;
	    }
	    switch (retval) {
	      case ST_CHECK:	/* check if hash is modified during iteration */
		if (PHASH(table, i) == 0 && PKEY(table, i) == never) {
		    break;
		}
		i = find_packed_index_from(table, hash, key, i);
		if (i >= table->real_entries) {
		    i = find_packed_index(table, hash, key);
		    if (i >= table->real_entries) goto deleted;
		}
		/* fall through */
	      case ST_CONTINUE:
		break;
	      case ST_STOP:
		return 0;
	      case ST_DELETE:
		remove_safe_packed_entry(table, i, never);
		break;
	    }
	}
	return 0;
    }

    head = st_head(table);
    list_for_each_safe(head, ptr, next, olist) {
	if (ptr->key != never) {
	    i = hash_pos(ptr->hash, table->num_bins);
	    retval = (*func)(ptr->key, ptr->record, arg, 0);
	  unpacked:
	    switch (retval) {
	      case ST_CHECK:	/* check if hash is modified during iteration */
		for (tmp = table->bins[i]; tmp != ptr; tmp = tmp->next) {
		    if (!tmp) {
		      deleted:
			/* call func with error notice */
			retval = (*func)(0, 0, arg, 1);
			return 1;
		    }
		}
		/* fall through */
	      case ST_CONTINUE:
		break;
	      case ST_STOP:
		return 0;
	      case ST_DELETE:
		last = &table->bins[hash_pos(ptr->hash, table->num_bins)];
		for (; (tmp = *last) != 0; last = &tmp->next) {
		    if (ptr == tmp) {
			remove_entry(table, ptr);
			ptr->key = ptr->record = never;
			ptr->hash = 0;
			break;
		    }
		}
		if (table->num_entries == 0) return 0;
	    }
	}
    }
    return 0;
}

int
st_foreach(st_table *table, int (*func)(ANYARGS), st_data_t arg)
{
    st_table_entry *ptr = 0, **last, *tmp, *next;
    enum st_retval retval;
    struct list_head *head;
    st_index_t i;

    if (table->entries_packed) {
	for (i = 0; i < table->real_entries; i++) {
	    st_data_t key, val;
	    st_index_t hash;
	    key = PKEY(table, i);
	    val = PVAL(table, i);
	    hash = PHASH(table, i);
	    retval = (*func)(key, val, arg, 0);
	    if (!table->entries_packed) {
		FIND_ENTRY(table, ptr, hash, i);
		if (!ptr) return 0;
		head = st_head(table);
		next = list_entry(ptr->olist.next, st_table_entry, olist);
		goto unpacked;
	    }
	    switch (retval) {
	      case ST_CONTINUE:
		break;
	      case ST_CHECK:
	      case ST_STOP:
		return 0;
	      case ST_DELETE:
		remove_packed_entry(table, i);
		i--;
		break;
	    }
	}
	return 0;
    }

    head = st_head(table);
    list_for_each_safe(head, ptr, next, olist) {
	i = hash_pos(ptr->hash, table->num_bins);
	retval = (*func)(ptr->key, ptr->record, arg, 0);
      unpacked:
	switch (retval) {
	  case ST_CONTINUE:
	    break;
	  case ST_CHECK:
	  case ST_STOP:
	    return 0;
	  case ST_DELETE:
	    last = &table->bins[hash_pos(ptr->hash, table->num_bins)];
	    for (; (tmp = *last) != 0; last = &tmp->next) {
		if (ptr == tmp) {
		    *last = ptr->next;
		    remove_entry(table, ptr);
		    st_free_entry(ptr);
		    break;
		}
	    }
	    if (table->num_entries == 0) return 0;
	}
    }
    return 0;
}

static st_index_t
get_keys(const st_table *table, st_data_t *keys, st_index_t size,
         int check, st_data_t never)
{
    st_data_t key;
    st_data_t *keys_start = keys;

    if (table->entries_packed) {
	st_index_t i;

	if (size > table->real_entries) size = table->real_entries;
	for (i = 0; i < size; i++) {
	    key = PKEY(table, i);
	    if (check && key == never) continue;
	    *keys++ = key;
	}
    }
    else {
	st_table_entry *ptr = 0;
	st_data_t *keys_end = keys + size;

	list_for_each(st_head(table), ptr, olist) {
	    if (keys >= keys_end) break;
	    key = ptr->key;
	    if (check && key == never) continue;
	    *keys++ = key;
	}
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

    if (table->entries_packed) {
	st_index_t i;

	if (size > table->real_entries) size = table->real_entries;
	for (i = 0; i < size; i++) {
	    key = PKEY(table, i);
	    if (check && key == never) continue;
	    *values++ = PVAL(table, i);
	}
    }
    else {
	st_table_entry *ptr = 0;
	st_data_t *values_end = values + size;

	list_for_each(st_head(table), ptr, olist) {
	    if (values >= values_end) break;
	    key = ptr->key;
	    if (check && key == never) continue;
	    *values++ = ptr->record;
	}
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

#if 0  /* unused right now */
int
st_reverse_foreach_check(st_table *table, int (*func)(ANYARGS), st_data_t arg, st_data_t never)
{
    st_table_entry *ptr, **last, *tmp, *next;
    struct list_head *head;
    enum st_retval retval;
    st_index_t i;

    if (table->entries_packed) {
	for (i = table->real_entries; 0 < i;) {
	    st_data_t key, val;
	    st_index_t hash;
	    --i;
	    key = PKEY(table, i);
	    val = PVAL(table, i);
	    hash = PHASH(table, i);
	    if (key == never) continue;
	    retval = (*func)(key, val, arg, 0);
	    if (!table->entries_packed) {
		FIND_ENTRY(table, ptr, hash, i);
		if (retval == ST_CHECK) {
		    if (!ptr) goto deleted;
		}
		if (table->num_entries == 0) return 0;
		head = st_head(table);
		next = list_entry(ptr->olist.next, st_table_entry, olist);
		goto unpacked;
	    }
	    switch (retval) {
	      case ST_CHECK:	/* check if hash is modified during iteration */
		if (PHASH(table, i) == 0 && PKEY(table, i) == never) {
		    break;
		}
		i = find_packed_index_from(table, hash, key, i);
		if (i >= table->real_entries) {
		    i = find_packed_index(table, hash, key);
		    if (i >= table->real_entries) goto deleted;
		}
		/* fall through */
	      case ST_CONTINUE:
		break;
	      case ST_STOP:
		return 0;
	      case ST_DELETE:
		remove_safe_packed_entry(table, i, never);
		break;
	    }
	}
	return 0;
    }

    head = st_head(table);
    list_for_each_rev_safe(head, ptr, next, olist) {
	if (ptr->key != never) {
	    i = hash_pos(ptr->hash, table->num_bins);
	    retval = (*func)(ptr->key, ptr->record, arg, 0);
	  unpacked:
	    switch (retval) {
	      case ST_CHECK:	/* check if hash is modified during iteration */
		for (tmp = table->bins[i]; tmp != ptr; tmp = tmp->next) {
		    if (!tmp) {
		      deleted:
			/* call func with error notice */
			retval = (*func)(0, 0, arg, 1);
			return 1;
		    }
		}
		/* fall through */
	      case ST_CONTINUE:
		break;
	      case ST_STOP:
		return 0;
	      case ST_DELETE:
		last = &table->bins[hash_pos(ptr->hash, table->num_bins)];
		for (; (tmp = *last) != 0; last = &tmp->next) {
		    if (ptr == tmp) {
			remove_entry(table, ptr);
			ptr->key = ptr->record = never;
			ptr->hash = 0;
			break;
		    }
		}
		if (table->num_entries == 0) return 0;
	    }
	}
    }
    return 0;
}

int
st_reverse_foreach(st_table *table, int (*func)(ANYARGS), st_data_t arg)
{
    st_table_entry *ptr, **last, *tmp, *next;
    enum st_retval retval;
    struct list_head *head;
    st_index_t i;

    if (table->entries_packed) {
	for (i = table->real_entries; 0 < i;) {
	    st_data_t key, val;
	    st_index_t hash;
	    --i;
	    key = PKEY(table, i);
	    val = PVAL(table, i);
	    hash = PHASH(table, i);
	    retval = (*func)(key, val, arg, 0);
	    if (!table->entries_packed) {
		FIND_ENTRY(table, ptr, hash, i);
		if (!ptr) return 0;
		head = st_head(table);
		next = list_entry(ptr->olist.next, st_table_entry, olist);
		goto unpacked;
	    }
	    switch (retval) {
	      case ST_CONTINUE:
		break;
	      case ST_CHECK:
	      case ST_STOP:
		return 0;
	      case ST_DELETE:
		remove_packed_entry(table, i);
		break;
	    }
	}
	return 0;
    }

    head = st_head(table);
    list_for_each_rev_safe(head, ptr, next, olist) {
	i = hash_pos(ptr->hash, table->num_bins);
	retval = (*func)(ptr->key, ptr->record, arg, 0);
      unpacked:
	switch (retval) {
	  case ST_CONTINUE:
	    break;
	  case ST_CHECK:
	  case ST_STOP:
	    return 0;
	  case ST_DELETE:
	    last = &table->bins[hash_pos(ptr->hash, table->num_bins)];
	    for (; (tmp = *last) != 0; last = &tmp->next) {
		if (ptr == tmp) {
		    *last = ptr->next;
		    remove_entry(table, ptr);
		    st_free_entry(ptr);
		    break;
		}
	    }
	    if (table->num_entries == 0) return 0;
	}
    }
    return 0;
}
#endif

#define FNV1_32A_INIT 0x811c9dc5

/*
 * 32 bit magic FNV-1a prime
 */
#define FNV_32_PRIME 0x01000193

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

/* MurmurHash described in https://en.wikipedia.org/wiki/MurmurHash */
/* 32bit is almost exactly MurmurHash3,
 * 64bit version is extrapolation of 32bit version */
#define BIG_CONSTANT(x,y) ((st_index_t)(x)<<32|(st_index_t)(y))
#define ROTL(x,n) ((x)<<(n)|(x)>>(SIZEOF_ST_INDEX_T*CHAR_BIT-(n)))

static inline st_index_t
murmur_step(st_index_t h, st_index_t k)
{
#if ST_INDEX_BITS <= 32
#define r1 (15)
#define r2 (13)
    const st_index_t c1 = 0xcc9e2d51;
    const st_index_t c2 = 0x1b873593;
    const st_index_t a = 0xe6546b64;
#else
#define r1 (31)
#define r2 (27)
    const st_index_t c1 = BIG_CONSTANT(0x87c37b91,0x114253d5);
    const st_index_t c2 = BIG_CONSTANT(0x4cf5ad43,0x2745937f);
    const st_index_t a = BIG_CONSTANT(0xe6546b64,0x38495ab5);
#endif
    k *= c1;
    k = ROTL(k, r1);
    k *= c2;

    h ^= k;
    h = ROTL(h, r2);
    h = h*5 + a;
    return h;
#undef r1
#undef r2
}

static inline st_index_t
murmur_finish(st_index_t h)
{
#if ST_INDEX_BITS <= 32
#define r1 (16)
#define r2 (13)
#define r3 (16)
    const st_index_t c1 = 0x85ebca6b;
    const st_index_t c2 = 0xc2b2ae35;
#else
/* values are taken from Mix13 on http://zimbry.blogspot.ru/2011/09/better-bit-mixing-improving-on.html */
#define r1 (30)
#define r2 (27)
#define r3 (31)
    const st_index_t c1 = BIG_CONSTANT(0xbf58476d,0x1ce4e5b9);
    const st_index_t c2 = BIG_CONSTANT(0x94d049bb,0x133111eb);
#endif
    h ^= h >> r1;
    h *= c1;
    h ^= h >> r2;
    h *= c2;
    h ^= h >> r3;
#if ST_INDEX_BITS > 64
    h *= c1;
    h ^= h >> r2;
    h *= c2;
    h ^= h >> r3;
#endif
    return h;
}

st_index_t
st_hash(const void *ptr, size_t len, st_index_t h)
{
    const char *data = ptr;
    st_index_t t = 0;
    size_t l = len;

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

	    if (len < (size_t)align) goto skip_tail;
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
# if !UNALIGNED_WORD_ACCESS
      skip_tail:
# endif
	h = murmur_step(h, t);
    }
    h ^= l;

    return murmur_finish(h);
}

st_index_t
st_hash_uint32(st_index_t h, uint32_t i)
{
    return murmur_step(h, i);
}

st_index_t
st_hash_uint(st_index_t h, st_index_t i)
{
    i += h;
/* no matter if it is BigEndian or LittleEndian,
 * we hash just integers */
#if SIZEOF_ST_INDEX_T*CHAR_BIT > 8*8
    h = murmur_step(h, i >> 8*8);
#endif
    h = murmur_step(h, i);
    return h;
}

st_index_t
st_hash_end(st_index_t h)
{
    h = murmur_finish(h);
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

PUREFUNC(static st_index_t strcasehash(st_data_t));
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
    enum {s1 = 11, s2 = 3};
    return (st_index_t)((n>>s1|(n<<s2)) ^ (n>>s2));
}
