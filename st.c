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

#ifndef ARG_UNUSED
#if defined(__GNUC__)
#  define ARG_UNUSED  __attribute__ ((unused))
#else
#  define ARG_UNUSED
#endif
#endif

typedef struct st_table_entry st_table_entry;
typedef struct st_list_entry st_list_entry;

struct st_table_entry {
    st_idx_t hash;
    st_idx_t next;
    st_data_t key;
    st_data_t record;
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
#define IDX_FILL 0xff
#define DELETED (0)
#define Z ((ssize_t)-1)

/* preparation for possible allocation improvements */
#define st_alloc_table() (st_table *)calloc(1, sizeof(st_table))
#define st_dealloc_table(table) sized_free(table, sizeof(st_table))

/* this calculation to satisfy jemalloc/tcmalloc allocation sizes */
static struct st_sizes {
    st_idx_t nentries, bin_mask;
} const st_sz[] = {
    { 0, 0 },
#if SIZEOF_VOIDP >= 8
/* def pws; a = 64; while a <= 2**32 * 24; yield a; yield a+a/2; a*=2; end; end
   def p2(v); [1,2,4,8,16].each{|i| v|=v>>i}; v; end
   to_enum(:pws).
      map{|v| m=v/24; k=p2(m); m=(v-k*4)/24)<k; [m,k]}.select{|m,k| m>10}.
      each_slice(2){|a| s=a.map{|m,k| "{ #{m}, #{k-1} },"}.join(" "); print "#{s}\n" } */
    { 4, 7 }, { 9, 7 },
    { 13, 15 }, { 18, 15 },
    { 26, 31 }, { 37, 31 },
    { 53, 63 }, { 74, 63 },
    { 106, 127 }, { 149, 127 },
    { 213, 255 }, { 298, 255 },
    { 426, 511 }, { 597, 511 },
    { 853, 1023 }, { 1194, 1023 },
    { 1706, 2047 }, { 2389, 2047 },
    { 3413, 4095 }, { 4778, 4095 },
    { 6826, 8191 }, { 9557, 8191 },
    { 13653, 16383 }, { 19114, 16383 },
    { 27306, 32767 }, { 38229, 32767 },
    { 54613, 65535 }, { 76458, 65535 },
    { 109226, 131071 }, { 152917, 131071 },
    { 218453, 262143 }, { 305834, 262143 },
    { 436906, 524287 }, { 611669, 524287 },
    { 873813, 1048575 }, { 1223338, 1048575 },
    { 1747626, 2097151 }, { 2446677, 2097151 },
    { 3495253, 4194303 }, { 4893354, 4194303 },
    { 6990506, 8388607 }, { 9786709, 8388607 },
    { 13981013, 16777215 }, { 19573418, 16777215 },
    { 27962026, 33554431 }, { 39146837, 33554431 },
    { 55924053, 67108863 }, { 78293674, 67108863 },
    { 111848106, 134217727 }, { 156587349, 134217727 },
    { 223696213, 268435455 }, { 313174698, 268435455 },
    { 447392426, 536870911 }, { 626349397, 536870911 },
    { 894784853, 1073741823 }, { 1252698794, 1073741823 },
    { 1789569706, 2147483647 }, { 2505397589, 2147483647 },
    { 3579139413, 4294967294 },
#elif SIZEOF_VOIDP == 4
/* def pws; a = 64; while a <= 2**32; yield a; yield a+a/2; a*=2; end
   to_enum(:pws).
      map{|v| m=v/24; k=p2(m); while (m=(v-k*4)/24)<k; k>>=1; end; [m,k]}.
      select{|m,k| m*24+k*4 < 2**32}.
      each_slice(2){|a| s=a.map{|m,k| "{ #{m}, #{k-1} },"}.join(" "); print "#{s}\n" } */
    { 3, 1 }, { 5, 3 },
    { 7, 3 }, { 10, 7 },
    { 14, 7 }, { 20, 15 },
    { 28, 15 }, { 40, 31 },
    { 56, 31 }, { 80, 63 },
    { 112, 63 }, { 160, 127 },
    { 224, 127 }, { 320, 255 },
    { 448, 255 }, { 640, 511 },
    { 896, 511 }, { 1280, 1023 },
    { 1792, 1023 }, { 2560, 2047 },
    { 3584, 2047 }, { 5120, 4095 },
    { 7168, 4095 }, { 10240, 8191 },
    { 14336, 8191 }, { 20480, 16383 },
    { 28672, 16383 }, { 40960, 32767 },
    { 57344, 32767 }, { 81920, 65535 },
    { 114688, 65535 }, { 163840, 131071 },
    { 229376, 131071 }, { 327680, 262143 },
    { 458752, 262143 }, { 655360, 524287 },
    { 917504, 524287 }, { 1310720, 1048575 },
    { 1835008, 1048575 }, { 2621440, 2097151 },
    { 3670016, 2097151 }, { 5242880, 4194303 },
    { 7340032, 4194303 }, { 10485760, 8388607 },
    { 14680064, 8388607 }, { 20971520, 16777215 },
    { 29360128, 16777215 }, { 41943040, 33554431 },
    { 58720256, 33554431 }, { 83886080, 67108863 },
    { 117440512, 67108863 },
#endif
    { 0, 0 }
};

/* shortcuts */

static inline st_idx_t
do_hash(st_data_t key, const st_table * table)
{
    st_idx_t h = (st_idx_t)(*table->type->hash)(key);
    return h != DELETED ? h : 0x71fe900d;
}
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

static st_list_entry*
st_alloc_list(int sz, st_idx_t fill) {
    if (sz != 0) {
	st_idx_t nen = st_sz[sz].nentries;
	st_list_entry* l = (st_list_entry*)calloc(nen, sizeof(st_list_entry));
#ifdef NOT_RUBY
	if (l == NULL) abort();
#endif
	return l;
    } else {
	return NULL;
    }
}

static st_list_entry*
st_grow_list(st_list_entry* l, int sz) {
    l = (st_list_entry*)sized_realloc(l,
	sizeof(st_list_entry)*st_sz[sz].nentries,
	sizeof(st_list_entry)*st_sz[sz-1].nentries);
#ifdef NOT_RUBY
    if (l == NULL) abort();
#endif
    return l;
}

static void
st_free_list(st_list_entry* l, int sz)
{
    sized_free(l, sizeof(st_list_entry)*st_sz[sz].nentries);
}

static inline void
st_free_data(st_table_entry* entries, int sz)
{
    if (entries != NULL) {
	sized_free(base_ptr(entries, sz), entries_size(sz));
    }
}

static inline st_table_entry*
st_grow_data(st_table_entry *e, int newsz, int oldsz)
{
    if (oldsz == 0) {
	if (newsz != 0) {
	    st_idx_t i, nen = st_sz[newsz].nentries;
	    st_idx_t* bins = (st_idx_t*)calloc(1, entries_size(newsz));
	    st_table_entry* en;
#ifdef NOTRUBY
	    if (bins == NULL) abort();
#endif
	    memset(bins, IDX_FILL, (st_sz[newsz].bin_mask + 1)*sizeof(st_idx_t));
	    en = entries_ptr(bins, newsz);
	    for (i = 0; i < nen-1; i++) {
		en[i].next = i+1;
		en[i].hash = DELETED;
	    }
	    en[nen-1].next = IDX_NULL;
	    en[nen-1].hash = DELETED;
	    return en;
	} else {
	    return (st_table_entry*)(fake_bins + 1);
	}
    } else {
	st_idx_t* bins = base_ptr(e, oldsz);
	st_idx_t i;
	st_idx_t en_old = st_sz[oldsz].nentries;
	st_idx_t en_new = st_sz[newsz].nentries;
	st_idx_t bins_old = st_sz[oldsz].bin_mask + 1;
	st_idx_t bins_new = st_sz[newsz].bin_mask + 1;
	st_table_entry* en;
	bins = sized_realloc(bins, entries_size(newsz), entries_size(oldsz));
#ifdef NOTRUBY
	if (bins == NULL) abort();
#endif
	if (bins_old < bins_new) {
	    MEMMOVE(bins + bins_new, bins + bins_old, st_table_entry, st_sz[oldsz].nentries);
	    memset(bins, IDX_FILL, bins_new*sizeof(st_idx_t));
	}
	en = entries_ptr(bins, newsz);
	for (i = en_old; i < en_new-1; i++) {
	    en[i].next = i+1;
	    en[i].hash = DELETED;
	}
	en[en_new-1].next = IDX_NULL;
	en[en_new-1].hash = DELETED;
	return en;
    }
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

static int
new_sz(st_idx_t size)
{
    int i;
    for (i = 1; st_sz[i].nentries != 0; i++)
        if (st_sz[i].nentries >= size)
            return i;
#ifndef NOT_RUBY
    rb_raise(rb_eRuntimeError, "st_table too big");
#endif
    return -1;			/* should raise exception */
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
    tbl->sz = new_sz(size);	/* round up to power-of-two */
    tbl->as.entries = st_grow_data(NULL, tbl->sz, 0);
    tbl->list = NULL;
    tbl->free = 0;
    tbl->rebuild_num = 0;
    tbl->first = IDX_NULL;
    tbl->last = IDX_NULL;

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
    st_free_list(table->list, table->sz);
    table->sz = 0;
    table->num_entries = 0;
    table->as.bins = &fake_bins[1];
    table->list = NULL;
    table->free = IDX_NULL;
    table->rebuild_num++;
    table->first = IDX_NULL;
    table->last = IDX_NULL;
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
    return sizeof(st_table) + entries_size(table->sz) +
	(table->list ? sizeof(st_list_entry)*st_sz[table->sz].nentries : 0);
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

static st_idx_t
find_entry(const st_table *table, st_data_t key)
{
    st_idx_t hash_val = do_hash(key, table);
    st_idx_t bin_pos = hash_pos(hash_val, table->sz);
    st_idx_t idx = table->as.bins[Z-bin_pos];
    FOUND_ENTRY;
    if (PTR_NOT_EQUAL(table, idx, hash_val, key)) {
	COLLISION;
	do {
	    idx = table->as.entries[idx].next;
	} while (PTR_NOT_EQUAL(table, idx, hash_val, key));
    }
    return idx;
}

static st_idx_t*
find_entry_ptr(const st_table *table, st_data_t key, st_idx_t hash_val,
           st_idx_t bin_pos)
{
    st_idx_t* idx = &table->as.bins[Z-bin_pos];
    FOUND_ENTRY;
    if (PTR_NOT_EQUAL(table, *idx, hash_val, key)) {
	COLLISION;
	do {
	    idx = &table->as.entries[*idx].next;
	} while (PTR_NOT_EQUAL(table, *idx, hash_val, key));
    }
    return idx;
}

#define collision_check 0

int
st_lookup(st_table *table, register st_data_t key, st_data_t *value)
{
    st_idx_t i = find_entry(table, key);

    if (i == IDX_NULL) {
	return 0;
    }
    else {
	if (value != 0) *value = table->as.entries[i].record;
	return 1;
    }
}

int
st_get_key(st_table *table, register st_data_t key, st_data_t *result)
{
    st_idx_t i = find_entry(table, key);

    if (i == IDX_NULL) {
	return 0;
    }
    else {
	if (result != 0)  *result = table->as.entries[i].key;
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
    if (table->list != NULL) {
	struct st_list_entry* l = &table->list[en_idx];
	l->next = IDX_NULL;
	if (table->first != IDX_NULL) {
	    l->prev = table->last;
	    table->list[table->last].next = en_idx;
	} else {
	    l->prev = IDX_NULL;
	    table->first = en_idx;
	}
    } else {
	if (table->first == IDX_NULL)
	    table->first = en_idx;
    }
    table->last = en_idx;
    table->num_entries++;
}

int
st_insert(register st_table *table, register st_data_t key, st_data_t value)
{
    st_idx_t hash_val, bin_pos, idx;

    hash_val = do_hash(key, table);
    bin_pos = hash_pos(hash_val, table->sz);
    idx = *find_entry_ptr(table, key, hash_val, bin_pos);

    if (idx == IDX_NULL) {
	add_direct(table, key, value, hash_val, bin_pos);
	return 0;
    }
    else {
	table->as.entries[idx].record = value;
	return 1;
    }
}

int
st_insert2(register st_table *table, register st_data_t key, st_data_t value,
	   st_data_t (*func)(st_data_t))
{
    st_idx_t hash_val, bin_pos, idx;

    hash_val = do_hash(key, table);
    bin_pos = hash_pos(hash_val, table->sz);
    idx = *find_entry_ptr(table, key, hash_val, bin_pos);

    if (idx == IDX_NULL) {
	key = (*func)(key);
	add_direct(table, key, value, hash_val, bin_pos);
	return 0;
    }
    else {
	table->as.entries[idx].record = value;
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
reclaim(register st_table *table)
{
    st_idx_t i, nen, prev;
    nen = st_sz[table->sz].nentries;
    table->list = st_alloc_list(table->sz, 0);
    prev = IDX_NULL;
    table->first = IDX_NULL;
    for (i = 0; i < nen; i++) {
	if (table->as.entries[i].hash == DELETED) {
	    table->as.entries[i].next = table->free;
	    table->free = i;
	} else {
	    table->list[i].prev = prev;
	    table->list[i].next = IDX_NULL;
	    if (prev == IDX_NULL)
		table->first = i;
	    else
		table->list[prev].next = i;
	    prev = i;
	}
    }
    table->last = prev;
}

static void
rehash(register st_table *table)
{
    st_idx_t i, hash_val, nen;

    nen = st_sz[table->sz].nentries;
    if (table->list == NULL && table->num_entries < nen - (nen >> 3)) {
	reclaim(table);
	return;
    }

    if (st_sz[table->sz + 1].nentries == 0) {
#ifndef NOT_RUBY
	rb_raise(rb_eRuntimeError, "hash is too big");
#else
	abort();
#endif
    }
    table->as.entries = st_grow_data(table->as.entries, table->sz+1, table->sz);
    table->sz++;
    table->free = nen;

    if (st_sz[table->sz].bin_mask != st_sz[table->sz-1].bin_mask) {
	for (i = 0; i < table->free; i++) {
	    if (table->as.entries[i].hash == DELETED)
		continue;
	    hash_val = hash_pos(table->as.entries[i].hash, table->sz);
	    table->as.entries[i].next = table->as.bins[Z-hash_val];
	    table->as.bins[Z-hash_val] = i;
	}
    }

    if (table->list != NULL) {
	table->list = st_grow_list(table->list, table->sz);
    }
}

st_table*
st_copy(st_table *old_table)
{
    st_table *new_table;

    new_table = st_alloc_table();
    *new_table = *old_table;

    new_table->as.entries = malloc(entries_size(new_table->sz));
    memcpy(new_table->as.entries, base_ptr(old_table->as.entries, old_table->sz),
            entries_size(new_table->sz));
    new_table->as.entries = entries_ptr((st_idx_t*)new_table->as.entries, new_table->sz);

    if (old_table->list != NULL) {
	new_table->list = malloc(sizeof(st_list_entry)*st_sz[new_table->sz].nentries);
	memcpy(new_table->list, old_table->list,
	    sizeof(st_list_entry)*st_sz[new_table->sz].nentries);
    }

    return new_table;
}

static inline void
remove_entry(st_table *table, st_idx_t idx)
{
    if (table->list != NULL) {
	st_list_entry* en = &table->list[idx];
	if (idx != table->last) {
	    table->list[en->next].prev = en->prev;
	} else {
	    table->last = en->prev;
	}
	if (idx != table->first) {
	    table->list[en->prev].next = en->next;
	} else {
	    table->first = en->next;
	}
	en->next = en->prev = IDX_NULL;
    } else if (table->first == idx) {
	if (table->num_entries > 0) {
	    table->first++;
	    while (table->first <= table->last &&
		    table->as.entries[table->first].hash == DELETED) {
		table->first++;
	    }
	} else {
	    table->first = table->last = IDX_NULL;
	}
    }
}

static inline void
free_entry(st_table *table, st_idx_t idx)
{
    if (table->list != NULL) {
	table->as.entries[idx].next = table->free;
	table->free = idx;
    }
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
	    if (value != 0) *value = ptr->record;
	    *key = ptr->key;
	    ptr->hash = DELETED;
	    ptr->key = ptr->record = 0;
	    table->num_entries--;
	    remove_entry(table, idx);
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
    st_idx_t hash_val, idx, *prev;
    register st_table_entry *ptr;

    hash_val = do_hash(*key, table);

    prev = &table->as.bins[Z-hash_pos(hash_val, table->sz)];

    for (; (idx = *prev) != IDX_NULL; prev = &ptr->next) {
        ptr = &table->as.entries[idx];
	if (ptr->hash != DELETED && EQUAL(table, *key, ptr)) {
	    *prev = ptr->next;
	    table->num_entries--;
	    *key = ptr->key;
	    if (value != 0) *value = ptr->record;
	    ptr->key = ptr->record = never;
	    ptr->hash = DELETED;
	    return 1;
	}
    }

    if (value != 0) *value = 0;
    return 0;
}

int
st_shift(register st_table *table, register st_data_t *key, st_data_t *value)
{
    st_table_entry *ptr;
    st_idx_t *prev;
    st_idx_t idx, first_idx;

    if (table->num_entries == 0) {
        if (value != 0) *value = 0;
        return 0;
    }

    if (table->list == NULL) {
	while (table->first <= table->last &&
		table->as.entries[table->first].hash == DELETED)
	    table->first++;
	if (table->first > table->last)
	    return 0;
    }
    first_idx = table->first;
    ptr = &table->as.entries[first_idx];
    prev = &table->as.bins[Z-hash_pos(ptr->hash, table->sz)];
    while ((idx = *prev) != first_idx) prev = &table->as.entries[idx].next;
    *prev = ptr->next;
    table->num_entries--;
    remove_entry(table, first_idx);
    if (value != 0) *value = ptr->record;
    *key = ptr->key;
    ptr->hash = DELETED;
    ptr->key = ptr->record = 0;
    free_entry(table, idx);
    return 1;
}

void
st_cleanup_safe(st_table *table, st_data_t never)
{
    st_idx_t head, next;

    head = table->first;
    if (table->list != NULL) {
	for (; head != IDX_NULL ; head = next) {
	    next = table->list[head].next;
	    if (table->as.entries[head].hash == DELETED) {
		remove_entry(table, head);
		free_entry(table, head);
	    }
	}
    } else if (head != IDX_NULL) {
	while (head <= table->last && table->as.entries[head].hash == DELETED)
	    head++;
	table->first = head;
    }
}

int
st_update(st_table *table, st_data_t key, st_update_callback_func *func, st_data_t arg)
{
    st_idx_t hash_val, bin_pos, *idx, tmp;
    register st_table_entry *ptr;
    st_data_t value = 0, old_key;
    int retval, existing = 0;

    hash_val = do_hash(key, table);
    bin_pos = hash_pos(hash_val, table->sz);
    idx = find_entry_ptr(table, key, hash_val, bin_pos);

    if (*idx != IDX_NULL) {
	ptr = &table->as.entries[*idx];
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
	    table->num_entries--;
	    tmp = *idx;
	    remove_entry(table, tmp);
	    *idx = ptr->next;
	    free_entry(table, tmp);
	    ptr->hash = DELETED;
	    ptr->key = ptr->record = 0;
	    break;
	}
	return existing;
    }
}

int
st_foreach_check(st_table *table, int (*func)(ANYARGS), st_data_t arg, st_data_t never)
{
    st_table_entry *ptr = 0;
    enum st_retval retval;
    st_idx_t idx, head, *last, hash;
    st_data_t key;

    for (head = table->first; head != IDX_NULL ;
	    head = table->list != NULL ?  table->list[head].next :
		(head < table->last ? head+1 : IDX_NULL)) {
	ptr = &table->as.entries[head];
	if (ptr->hash != DELETED) {
	    key = ptr->key;
	    retval = (*func)(key, ptr->record, arg, 0);
	    switch (retval) {
	      case ST_CHECK:	/* check if hash is modified during iteration */
		ptr = &table->as.entries[head];
		if (ptr->hash != DELETED && ptr->key != key) {
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
			    *last = ptr->next;
			    ptr->key = ptr->record = never;
			    ptr->hash = DELETED;
			    table->num_entries--;
			}
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
    st_table_entry *ptr = 0;
    enum st_retval retval;
    st_idx_t head, next, *last, idx;

    if (table->num_entries == 0) {
        return 0;
    }

    for (head = table->first; head != IDX_NULL ; head = next) {
	ptr = &table->as.entries[head];
	if (table->list == NULL)
	    next = (head < table->last && table->last != IDX_NULL) ? head+1 : IDX_NULL;
	else
	    next = table->list[head].next;
	if (ptr->hash != DELETED) {
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
			ptr->key = ptr->record = 0;
			ptr->hash = DELETED;
			table->num_entries--;
			remove_entry(table, idx);
			free_entry(table, idx);
			break;
		    }
		}
		if (table->num_entries == 0) return 0;
	    }
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

    st_table_entry *ptr = 0;
    st_data_t *keys_end = keys + size;
    
    st_idx_t idx = table->first;

    if (table->list != NULL) {
	while (idx != IDX_NULL) {
	    ptr = &table->as.entries[idx];
	    if (ptr->hash != DELETED) {
		if (keys >= keys_end) break;
		key = ptr->key;
		if (check && key == never) continue;
		*keys++ = key;
	    }
	    idx = table->list[idx].next;
	}
    } else if (idx != IDX_NULL) {
	ptr = &table->as.entries[idx];
	while (idx <= table->last) {
	    if (ptr->hash != DELETED) {
		if (keys >= keys_end) break;
		key = ptr->key;
		if (check && key == never) continue;
		*keys++ = key;
	    }
	    idx++; ptr++;
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

    st_table_entry *ptr = 0;
    st_data_t *values_end = values + size;

    st_idx_t idx = table->first;

    if (table->list != NULL) {
	while (idx != IDX_NULL) {
	    ptr = &table->as.entries[idx];
	    if (ptr->hash != DELETED) {
		if (values >= values_end) break;
		key = ptr->key;
		if (check && key == never) continue;
		*values++ = ptr->record;
	    }
	    idx = table->list[idx].next;
	}
    } else if (idx != IDX_NULL) {
	ptr = &table->as.entries[idx];
	while (idx <= table->last) {
	    if (ptr->hash != DELETED) {
		if (values >= values_end) break;
		key = ptr->key;
		if (check && key == never) continue;
		*values++ = ptr->record;
	    }
	    idx++; ptr++;
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
