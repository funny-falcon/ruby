/* This file is included by symbol.c */

#include "id_table.h"

#ifndef ID_TABLE_DEBUG
#define ID_TABLE_DEBUG 0
#endif

typedef rb_id_serial_t id_key_t;

static inline ID
key2id(id_key_t key)
{
    return rb_id_serial_to_id(key);
}

static inline id_key_t
id2key(ID id)
{
    return rb_id_to_serial(id);
}

/* simple open addressing with quadratic probing.
   uses mark-bit on collisions - need extra 1 bit,
   ID is strictly 3 bits larger than rb_id_serial_t */

struct rb_id_table {
    int capa;
    int num;
    int used;
    id_key_t *keys;
};

#define ITEM_GET_KEY(tbl, i) ((tbl)->keys[i] >> 1)
#define ITEM_KEY_ISSET(tbl, i) ((tbl)->keys[i] > 1)
#define ITEM_COLLIDED(tbl, i) ((tbl)->keys[i] & 1)
#define ITEM_SET_COLLIDED(tbl, i) ((tbl)->keys[i] |= 1)
static inline void
ITEM_SET_KEY(struct rb_id_table *tbl, int i, id_key_t key)
{
    tbl->keys[i] = (key << 1) | ITEM_COLLIDED(tbl, i);
}
#define ID_TABLE_VALUES(tbl) ((VALUE*)((tbl)->keys+(tbl)->capa))
#define ITEM_GET_VALUE(tbl, i) (ID_TABLE_VALUES(tbl)[i])
static inline void
ITEM_SET_VALUE(struct rb_id_table *tbl, int i, VALUE val)
{
    ID_TABLE_VALUES(tbl)[i] = val;
}
#define ITEM_SIZE (sizeof(id_key_t) + sizeof(VALUE))

static inline int
round_capa(int capa)
{
    /* minsize is 4 */
    capa >>= 2;
    capa |= capa >> 1;
    capa |= capa >> 2;
    capa |= capa >> 4;
    capa |= capa >> 8;
    capa |= capa >> 16;
    return (capa + 1) << 2;
}

static struct rb_id_table *
rb_id_table_init(struct rb_id_table *tbl, int capa)
{
    MEMZERO(tbl, struct rb_id_table, 1);
    if (capa > 0) {
	capa = round_capa(capa);
	tbl->capa = (int)capa;
	tbl->keys = (id_key_t*)ruby_xcalloc(capa, ITEM_SIZE);
    }
    return tbl;
}

struct rb_id_table *
rb_id_table_create(size_t capa)
{
    struct rb_id_table *tbl = ALLOC(struct rb_id_table);
    return rb_id_table_init(tbl, (int)capa);
}

void
rb_id_table_free(struct rb_id_table *tbl)
{
    xfree(tbl->keys);
    xfree(tbl);
}

void
rb_id_table_clear(struct rb_id_table *tbl)
{
    tbl->num = 0;
    tbl->used = 0;
    memset(tbl->keys, 0, tbl->capa * ITEM_SIZE);
}

size_t
rb_id_table_size(const struct rb_id_table *tbl)
{
    return (size_t)tbl->num;
}

size_t
rb_id_table_memsize(const struct rb_id_table *tbl)
{
    return ITEM_SIZE * (size_t)tbl->capa + sizeof(struct rb_id_table);
}

static int
hash_table_index(struct rb_id_table* tbl, id_key_t key)
{
    if (tbl->capa > 0) {
	int mask = tbl->capa - 1;
	int ix = key & mask;
	id_key_t mix = tbl->capa > 64 ? key : 0;
	int d = 1;
	while (key != ITEM_GET_KEY(tbl, ix)) {
	    if (!ITEM_COLLIDED(tbl, ix))
		return -1;
	    ix = (ix + d) & mask;
	    d += 1 + (mix >>= 7);
	}
	return ix;
    }
    return -1;
}

static void
hash_table_raw_insert(struct rb_id_table *tbl, id_key_t key, VALUE val)
{
    int mask = tbl->capa - 1;
    int ix = key & mask;
    id_key_t mix = tbl->capa > 64 ? key : 0;
    int d = 1;
#if ID_TABLE_DEBUG
    assert(key > 0);
#endif
    while (ITEM_KEY_ISSET(tbl, ix)) {
	ITEM_SET_COLLIDED(tbl, ix);
	ix = (ix + d) & mask;
	d += 1 + (mix >>= 7);
    }
    tbl->num++;
    if (!ITEM_COLLIDED(tbl, ix)) {
	tbl->used++;
    }
    ITEM_SET_KEY(tbl, ix, key);
    ITEM_SET_VALUE(tbl, ix, val);
}

static int
hash_delete_index(struct rb_id_table *tbl, int ix)
{
    if (ix >= 0) {
	if (!ITEM_COLLIDED(tbl, ix)) {
	    tbl->used--;
	}
	tbl->num--;
	ITEM_SET_KEY(tbl, ix, 0);
	ITEM_SET_VALUE(tbl, ix, 0);
	return TRUE;
    } else {
	return FALSE;
    }
}

static void
hash_table_extend(struct rb_id_table* tbl)
{
    /* fill rate 66% */
    if (tbl->used + (tbl->used >> 1) >= tbl->capa) {
	struct rb_id_table tmp_tbl;
	int i;
	id_key_t* old;
	VALUE* values = ID_TABLE_VALUES(tbl);
	rb_id_table_init(&tmp_tbl, tbl->num + (tbl->num >> 1) + 1);
	for (i = 0; i < tbl->capa; i++) {
	    id_key_t key = ITEM_GET_KEY(tbl, i);
	    if (key != 0) {
		hash_table_raw_insert(&tmp_tbl, key, values[i]);
	    }
	}
	old = tbl->keys;
	*tbl = tmp_tbl;
	xfree(old);
    }
}

#if ID_TABLE_DEBUG && 0
static void
hash_table_show(struct rb_id_table *tbl)
{
    const id_key_t *keys = tbl->keys;
    const int capa = tbl->capa;
    int i;

    fprintf(stderr, "tbl: %p (capa: %d, num: %d, used: %d)\n", tbl, tbl->capa, tbl->num, tbl->used);
    for (i=0; i<capa; i++) {
	if (ITEM_KEY_ISSET(tbl, i)) {
	    fprintf(stderr, " -> [%d] %s %d\n", i, rb_id2name(key2id(keys[i])), (int)keys[i]);
	}
    }
}
#endif

int
rb_id_table_lookup(struct rb_id_table *tbl, ID id, VALUE *valp)
{
    id_key_t key = id2key(id);
    int index = hash_table_index(tbl, key);

    if (index >= 0) {
	*valp = ITEM_GET_VALUE(tbl, index);
	return TRUE;
    }
    else {
	return FALSE;
    }
}

static int
rb_id_table_insert_key(struct rb_id_table *tbl, const id_key_t key, const VALUE val)
{
    const int index = hash_table_index(tbl, key);

    if (index >= 0) {
	ITEM_SET_VALUE(tbl, index, val);
    }
    else {
	hash_table_extend(tbl);
	hash_table_raw_insert(tbl, key, val);
    }
    return TRUE;
}

int
rb_id_table_insert(struct rb_id_table *tbl, ID id, VALUE val)
{
    return rb_id_table_insert_key(tbl, id2key(id), val);
}

int
rb_id_table_delete(struct rb_id_table *tbl, ID id)
{
    const id_key_t key = id2key(id);
    int index = hash_table_index(tbl, key);
    return hash_delete_index(tbl, index);
}

void
rb_id_table_foreach(struct rb_id_table *tbl, rb_id_table_foreach_func_t *func, void *data)
{
    int i, capa = tbl->capa;

    for (i=0; i<capa; i++) {
	if (ITEM_KEY_ISSET(tbl, i)) {
	    const id_key_t key = ITEM_GET_KEY(tbl, i);
	    const VALUE val = ITEM_GET_VALUE(tbl, i);
	    enum rb_id_table_iterator_result ret = (*func)(key2id(key), val, data);

	    if (ret == ID_TABLE_DELETE)
		hash_delete_index(tbl, i);
	    else if (ret == ID_TABLE_STOP)
		return;
	}
    }
}

void
rb_id_table_foreach_values(struct rb_id_table *tbl, rb_id_table_foreach_values_func_t *func, void *data)
{
    int i, capa = tbl->capa;

    for (i=0; i<capa; i++) {
	if (ITEM_KEY_ISSET(tbl, i)) {
	    const VALUE val = ITEM_GET_VALUE(tbl, i);
	    enum rb_id_table_iterator_result ret = (*func)(val, data);

	    if (ret == ID_TABLE_DELETE)
		hash_delete_index(tbl, i);
	    else if (ret == ID_TABLE_STOP)
		return;
	}
    }
}
