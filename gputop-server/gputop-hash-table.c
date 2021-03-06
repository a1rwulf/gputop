/*
 * Copyright © 2009,2012 Intel Corporation
 * Copyright © 1988-2004 Keith Packard and Bart Massey.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Except as contained in this notice, the names of the authors
 * or their institutions shall not be used in advertising or
 * otherwise to promote the sale, use or other dealings in this
 * Software without prior written authorization from the
 * authors.
 *
 * Authors:
 *    Eric Anholt <eric@anholt.net>
 *    Keith Packard <keithp@keithp.com>
 */

/**
 * Implements an open-addressing, linear-reprobing gputop_hash table.
 *
 * For more information, see:
 *
 * http://cgit.freedesktop.org/~anholt/hash_table/tree/README
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "gputop-hash-table.h"
#include "gputop-util.h"

/* Compute the size of an array */
#ifndef ARRAY_SIZE
#  define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#endif

static const uint32_t deleted_key_value;

/**
 * From Knuth -- a good choice for gputop_hash/rehash values is p, p-2 where
 * p and p-2 are both prime.  These tables are sized to have an extra 10%
 * free to avoid exponential performance degradation as the gputop_hash table fills
 */
static const struct {
    uint32_t max_entries, size, rehash;
} hash_sizes[] = {
    { 2,			5,		3	  },
    { 4,			7,		5	  },
    { 8,			13,		11	  },
    { 16,		19,		17	  },
    { 32,		43,		41        },
    { 64,		73,		71        },
    { 128,		151,		149       },
    { 256,		283,		281       },
    { 512,		571,		569       },
    { 1024,		1153,		1151      },
    { 2048,		2269,		2267      },
    { 4096,		4519,		4517      },
    { 8192,		9013,		9011      },
    { 16384,		18043,		18041     },
    { 32768,		36109,		36107     },
    { 65536,		72091,		72089     },
    { 131072,		144409,		144407    },
    { 262144,		288361,		288359    },
    { 524288,		576883,		576881    },
    { 1048576,		1153459,	1153457   },
    { 2097152,		2307163,	2307161   },
    { 4194304,		4613893,	4613891   },
    { 8388608,		9227641,	9227639   },
    { 16777216,		18455029,	18455027  },
    { 33554432,		36911011,	36911009  },
    { 67108864,		73819861,	73819859  },
    { 134217728,		147639589,	147639587 },
    { 268435456,		295279081,	295279079 },
    { 536870912,		590559793,	590559791 },
    { 1073741824,	1181116273,	1181116271},
    { 2147483648ul,	2362232233ul,	2362232231ul}
};

static int
entry_is_free(const struct gputop_hash_entry *entry)
{
    return entry->key == NULL;
}

static int
entry_is_deleted(const struct gputop_hash_table *ht, struct gputop_hash_entry *entry)
{
    return entry->key == ht->deleted_key;
}

static int
entry_is_present(const struct gputop_hash_table *ht, struct gputop_hash_entry *entry)
{
    return entry->key != NULL && entry->key != ht->deleted_key;
}

struct gputop_hash_table *
gputop_hash_table_create(uint32_t (*key_hash_function)(const void *key),
                         bool (*key_equals_function)(const void *a,
                                                     const void *b))
{
    struct gputop_hash_table *ht;

    ht = xmalloc(sizeof(struct gputop_hash_table));
    if (ht == NULL)
        return NULL;

    ht->size_index = 0;
    ht->size = hash_sizes[ht->size_index].size;
    ht->rehash = hash_sizes[ht->size_index].rehash;
    ht->max_entries = hash_sizes[ht->size_index].max_entries;
    ht->key_hash_function = key_hash_function;
    ht->key_equals_function = key_equals_function;
    ht->table = xmalloc0(sizeof (struct gputop_hash_entry) * ht->size);
    ht->entries = 0;
    ht->deleted_entries = 0;
    ht->deleted_key = &deleted_key_value;

    if (ht->table == NULL) {
        free(ht);
        return NULL;
    }

    return ht;
}

/**
 * Frees the given gputop_hash table.
 *
 * If delete_function is passed, it gets called on each entry present before
 * freeing.
 */
void
gputop_hash_table_destroy(struct gputop_hash_table *ht,
                          void (*delete_function)
                          (struct gputop_hash_entry *entry))
{
    if (!ht)
        return;

    if (delete_function) {
        struct gputop_hash_entry *entry;

        gputop_hash_table_foreach(ht, entry) {
            delete_function(entry);
        }
    }
    free(ht);
}

/** Sets the value of the key pointer used for deleted entries in the table.
 *
 * The assumption is that usually keys are actual pointers, so we use a
 * default value of a pointer to an arbitrary piece of storage in the library.
 * But in some cases a consumer wants to store some other sort of value in the
 * table, like a uint32_t, in which case that pointer may conflict with one of
 * their valid keys.  This lets that user select a safe value.
 *
 * This must be called before any keys are actually deleted from the table.
 */
void
gputop_hash_table_set_deleted_key(struct gputop_hash_table *ht,
                                  const void *deleted_key)
{
    ht->deleted_key = deleted_key;
}

static struct gputop_hash_entry *
hash_table_search(struct gputop_hash_table *ht, uint32_t gputop_hash,
                  const void *key)
{
    uint32_t start_hash_address = gputop_hash % ht->size;
    uint32_t hash_address = start_hash_address;

    do {
        uint32_t double_hash;

        struct gputop_hash_entry *entry = ht->table + hash_address;

        if (entry_is_free(entry)) {
            return NULL;
        } else if (entry_is_present(ht, entry) && entry->hash == gputop_hash) {
            if (ht->key_equals_function(key, entry->key)) {
                return entry;
            }
        }

        double_hash = 1 + gputop_hash % ht->rehash;

        hash_address = (hash_address + double_hash) % ht->size;
    } while (hash_address != start_hash_address);

    return NULL;
}

/**
 * Finds a gputop_hash table entry with the given key and gputop_hash of that key.
 *
 * Returns NULL if no entry is found.  Note that the data pointer may be
 * modified by the user.
 */
struct gputop_hash_entry *
gputop_hash_table_search(struct gputop_hash_table *ht, const void *key)
{
    assert(ht->key_hash_function);
    return hash_table_search(ht, ht->key_hash_function(key), key);
}

struct gputop_hash_entry *
gputop_hash_table_search_pre_hashed(struct gputop_hash_table *ht,
                                    uint32_t gputop_hash, const void *key)
{
    assert(ht->key_hash_function == NULL ||
           gputop_hash == ht->key_hash_function(key));
    return hash_table_search(ht, gputop_hash, key);
}

static struct gputop_hash_entry *
hash_table_insert(struct gputop_hash_table *ht, uint32_t gputop_hash,
                  const void *key, void *data);

static void
gputop_hash_table_rehash(struct gputop_hash_table *ht, unsigned new_size_index)
{
    struct gputop_hash_table old_ht;
    struct gputop_hash_entry *table, *entry;

    if (new_size_index >= ARRAY_SIZE(hash_sizes))
        return;

    table = xmalloc0(sizeof (struct gputop_hash_entry) *
    hash_sizes[new_size_index].size);
    if (table == NULL)
        return;

    old_ht = *ht;

    ht->table = table;
    ht->size_index = new_size_index;
    ht->size = hash_sizes[ht->size_index].size;
    ht->rehash = hash_sizes[ht->size_index].rehash;
    ht->max_entries = hash_sizes[ht->size_index].max_entries;
    ht->entries = 0;
    ht->deleted_entries = 0;

    gputop_hash_table_foreach(&old_ht, entry) {
        hash_table_insert(ht, entry->hash, entry->key, entry->data);
    }

    free(old_ht.table);
}

static struct gputop_hash_entry *
hash_table_insert(struct gputop_hash_table *ht, uint32_t gputop_hash,
                  const void *key, void *data)
{
    uint32_t start_hash_address, hash_address;
    struct gputop_hash_entry *available_entry = NULL;

    if (ht->entries >= ht->max_entries) {
        gputop_hash_table_rehash(ht, ht->size_index + 1);
    } else if (ht->deleted_entries + ht->entries >= ht->max_entries) {
        gputop_hash_table_rehash(ht, ht->size_index);
    }

    start_hash_address = gputop_hash % ht->size;
    hash_address = start_hash_address;
    do {
        struct gputop_hash_entry *entry = ht->table + hash_address;
        uint32_t double_hash;

        if (!entry_is_present(ht, entry)) {
            /* Stash the first available entry we find */
            if (available_entry == NULL)
                available_entry = entry;
            if (entry_is_free(entry))
                break;
        }

        /* Implement replacement when another insert happens
         * with a matching key.  This is a relatively common
         * feature of gputop_hash tables, with the alternative
         * generally being "insert the new value as well, and
         * return it first when the key is searched for".
         *
         * Note that the gputop_hash table doesn't have a delete
         * callback.  If freeing of old data pointers is
         * required to avoid memory leaks, perform a search
         * before inserting.
         */
        if (entry->hash == gputop_hash &&
            ht->key_equals_function(key, entry->key)) {
            entry->key = key;
            entry->data = data;
            return entry;
        }


        double_hash = 1 + gputop_hash % ht->rehash;

        hash_address = (hash_address + double_hash) % ht->size;
    } while (hash_address != start_hash_address);

    if (available_entry) {
        if (entry_is_deleted(ht, available_entry))
        ht->deleted_entries--;
        available_entry->hash = gputop_hash;
        available_entry->key = key;
        available_entry->data = data;
        ht->entries++;
        return available_entry;
    }

    /* We could hit here if a required resize failed. An unchecked-malloc
     * application could ignore this result.
     */
    return NULL;
}

/**
 * Inserts the key with the given gputop_hash into the table.
 *
 * Note that insertion may rearrange the table on a resize or rehash,
 * so previously found gputop_hash_entries are no longer valid after this function.
 */
struct gputop_hash_entry *
gputop_hash_table_insert(struct gputop_hash_table *ht, const void *key,
                         void *data)
{
    assert(ht->key_hash_function);
    return hash_table_insert(ht, ht->key_hash_function(key), key, data);
}

struct gputop_hash_entry *
gputop_hash_table_insert_pre_hashed(struct gputop_hash_table *ht,
                                    uint32_t gputop_hash, const void *key,
                                    void *data)
{
    assert(ht->key_hash_function == NULL ||
           gputop_hash == ht->key_hash_function(key));
    return hash_table_insert(ht, gputop_hash, key, data);
}

/**
 * This function deletes the given gputop_hash table entry.
 *
 * Note that deletion doesn't otherwise modify the table, so an iteration over
 * the table deleting entries is safe.
 */
void
gputop_hash_table_remove(struct gputop_hash_table *ht,
                         struct gputop_hash_entry *entry)
{
    if (!entry)
        return;

    entry->key = ht->deleted_key;
    ht->entries--;
    ht->deleted_entries++;
}

/**
 * This function is an iterator over the gputop_hash table.
 *
 * Pass in NULL for the first entry, as in the start of a for loop.  Note that
 * an iteration over the table is O(table_size) not O(entries).
 */
struct gputop_hash_entry *
gputop_hash_table_next_entry(struct gputop_hash_table *ht,
                             struct gputop_hash_entry *entry)
{
    if (entry == NULL)
        entry = ht->table;
    else
        entry = entry + 1;

    for (; entry != ht->table + ht->size; entry++) {
        if (entry_is_present(ht, entry)) {
            return entry;
        }
    }

    return NULL;
}

/**
 * Returns a random entry from the gputop_hash table.
 *
 * This may be useful in implementing random replacement (as opposed
 * to just removing everything) in caches based on this gputop_hash table
 * implementation.  @predicate may be used to filter entries, or may
 * be set to NULL for no filtering.
 */
struct gputop_hash_entry *
gputop_hash_table_random_entry(struct gputop_hash_table *ht,
                               bool (*predicate)
                               (struct gputop_hash_entry *entry))
{
    struct gputop_hash_entry *entry;
    uint32_t i = rand() % ht->size;

    if (ht->entries == 0)
        return NULL;

    for (entry = ht->table + i; entry != ht->table + ht->size; entry++) {
        if (entry_is_present(ht, entry) &&
            (!predicate || predicate(entry))) {
            return entry;
        }
    }

    for (entry = ht->table; entry != ht->table + i; entry++) {
        if (entry_is_present(ht, entry) &&
            (!predicate || predicate(entry))) {
            return entry;
        }
    }

    return NULL;
}


/**
 * Quick FNV-1a gputop_hash implementation based on:
 * http://www.isthe.com/chongo/tech/comp/fnv/
 *
 * FNV-1a is not be the best gputop_hash out there -- Jenkins's lookup3 is supposed
 * to be quite good, and it probably beats FNV.  But FNV has the advantage
 * that it involves almost no code.  For an improvement on both, see Paul
 * Hsieh's http://www.azillionmonkeys.com/qed/hash.html
 */
uint32_t
gputop_hash_data(const void *data, size_t size)
{
    return gputop_fnv32_1a_accumulate_block(gputop_fnv32_1a_offset_bias,
                                            data, size);
}

/** FNV-1a string gputop_hash implementation */
uint32_t
gputop_hash_string(const char *key)
{
    uint32_t gputop_hash = gputop_fnv32_1a_offset_bias;

    while (*key != 0) {
        gputop_hash = gputop_fnv32_1a_accumulate(gputop_hash, *key);
        key++;
    }

    return gputop_hash;
}

/**
 * String compare function for use as the comparison callback in
 * gputop_hash_table_create().
 */
bool
gputop_key_string_equal(const void *a, const void *b)
{
    return strcmp(a, b) == 0;
}

bool
gputop_key_pointer_equal(const void *a, const void *b)
{
    return a == b;
}
