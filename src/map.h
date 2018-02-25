#ifndef _HSK_MAP_H
#define _HSK_MAP_H

/*
 * Parts of this software are based on khash.h:
 *
 *  The MIT License
 *
 *  Copyright (c) 2008, 2009, 2011 by Attractive Chaos <attractor@live.co.uk>
 *
 *  Permission is hereby granted, free of charge, to any person obtaining
 *  a copy of this software and associated documentation files (the
 *  "Software"), to deal in the Software without restriction, including
 *  without limitation the rights to use, copy, modify, merge, publish,
 *  distribute, sublicense, and/or sell copies of the Software, and to
 *  permit persons to whom the Software is furnished to do so, subject to
 *  the following conditions:
 *
 *  The above copyright notice and this permission notice shall be
 *  included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 *  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 *  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>

typedef uint32_t (*hsk_map_hash_func)(void *key);
typedef bool (*hsk_map_equal_func)(void *a, void *b);
typedef void (*hsk_map_free_func)(void *ptr);

typedef struct hsk_map_s {
  uint32_t n_buckets;
  uint32_t size;
  uint32_t n_occupied;
  uint32_t upper_bound;
  uint32_t *flags;
  void **keys;
  void **vals;
  bool is_map;
  hsk_map_hash_func hash_func;
  hsk_map_equal_func equal_func;
  hsk_map_free_func free_func;
} hsk_map_t;

typedef uint32_t hsk_map_iter_t;

#define __hsk_isempty(f, i) ((f[i >> 4] >> ((i & 0xfu) << 1)) & 2)
#define __hsk_isdel(f, i) ((f[i >> 4] >> ((i & 0xfu) << 1)) & 1)
#define __hsk_iseither(f, i) ((f[i >> 4] >> ((i & 0xfu) << 1)) & 3)
#define __hsk_set_isdel_false(f, i) (f[i >> 4] &= ~(1ul << ((i & 0xfu) << 1)))
#define __hsk_set_isempty_false(f, i) (f[i >> 4] &= ~(2ul << ((i & 0xfu) << 1)))
#define __hsk_set_isboth_false(f, i) (f[i >> 4] &= ~(3ul << ((i & 0xfu) << 1)))
#define __hsk_set_isdel_true(f, i) (f[i >> 4] |= 1ul << ((i & 0xfu) << 1))
#define __hsk_fsize(m) ((m) < 16 ? 1 : (m) >> 4)
#define __hsk_roundup32(x) \
  do {                     \
    --(x);                 \
    (x) |= (x) >> 1;       \
    (x) |= (x) >> 2;       \
    (x) |= (x) >> 4;       \
    (x) |= (x) >> 8;       \
    (x) |= (x) >> 16;      \
    ++(x);                 \
  } while (0)

static const double __hsk_hash_upper = 0.77;

#define hsk_map_begin(map) ((hsk_map_iter_t)0)
#define hsk_map_end(map) ((map)->n_buckets)
#define hsk_map_exists(map, i) (!__hsk_iseither((map)->flags, (i)))
#define hsk_map_key(map, i) ((map)->keys[i])
#define hsk_map_value(map, i) ((map)->vals[i])

#define hsk_map_each(map, kvar, vvar, code)                         \
  do {                                                              \
    hsk_map_iter_t __i;                                             \
    for (__i = hsk_map_begin(map); __i < hsk_map_end(map); __i++) { \
      if (!hsk_map_exists(map, i))                                  \
        continue;                                                   \
                                                                    \
      (kvar) = hsk_map_key(map, __i);                               \
      (vvar) = hsk_map_value(map, __i);                             \
                                                                    \
      code;                                                         \
    }                                                               \
  } while (0)

#define hsk_map_each_value(map, vvar, code)                         \
  do {                                                              \
    hsk_map_iter_t __i;                                             \
    for (__i = hsk_map_begin(map); __i < hsk_map_end(map); __i++) { \
      if (!hsk_map_exists(map, i))                                  \
        continue;                                                   \
                                                                    \
      (vvar) = hsk_map_value(map, __i);                             \
                                                                    \
      code;                                                         \
    }                                                               \
  } while (0)

void
hsk_map_init(
  hsk_map_t *map,
  bool is_map,
  hsk_map_hash_func hash_func,
  hsk_map_equal_func equal_func,
  hsk_map_free_func free_func
);

void
hsk_map_init_map(
  hsk_map_t *map,
  hsk_map_hash_func hash_func,
  hsk_map_equal_func equal_func,
  hsk_map_free_func free_func
);

void
hsk_map_init_set(
  hsk_map_t *map,
  hsk_map_hash_func hash_func,
  hsk_map_equal_func equal_func
);

void
hsk_map_init_hash_map(hsk_map_t *map, hsk_map_free_func free_func);

void
hsk_map_init_hash_set(hsk_map_t *map);

void
hsk_map_init_str_map(hsk_map_t *map, hsk_map_free_func free_func);

void
hsk_map_init_str_set(hsk_map_t *map);

void
hsk_map_init_int_map(hsk_map_t *map, hsk_map_free_func free_func);

void
hsk_map_init_int_set(hsk_map_t *map);

void
hsk_map_uninit(hsk_map_t *map);

hsk_map_t *
hsk_map_alloc(
  bool is_map,
  hsk_map_hash_func hash_func,
  hsk_map_equal_func equal_func,
  hsk_map_free_func free_func
);

hsk_map_t *
hsk_map_alloc_map(
  hsk_map_hash_func hash_func,
  hsk_map_equal_func equal_func,
  hsk_map_free_func free_func
);

hsk_map_t *
hsk_map_alloc_set(
  hsk_map_hash_func hash_func,
  hsk_map_equal_func equal_func
);

hsk_map_t *
hsk_map_alloc_hash_map(hsk_map_free_func free_func);

hsk_map_t *
hsk_map_alloc_hash_set(void);

hsk_map_t *
hsk_map_alloc_str_map(hsk_map_free_func free_func);

hsk_map_t *
hsk_map_alloc_str_set(void);

hsk_map_t *
hsk_map_alloc_int_map(hsk_map_free_func free_func);

hsk_map_t *
hsk_map_alloc_int_set(void);

void
hsk_map_free(hsk_map_t *map);

void
hsk_map_deep_free(hsk_map_t *map);

void
hsk_map_reset(hsk_map_t *map);

uint32_t
hsk_map_lookup(hsk_map_t *map, void *key);

int32_t
hsk_map_resize(hsk_map_t *map, uint32_t new_n_buckets);

uint32_t
hsk_map_put(hsk_map_t *map, void *key, int *ret);

void
hsk_map_delete(hsk_map_t *map, uint32_t x);

void
hsk_map_clear(hsk_map_t *map);

bool
hsk_map_set(hsk_map_t *map, void *key, void *value);

void *
hsk_map_get(hsk_map_t *map, void *key);

bool
hsk_map_has(hsk_map_t *map, void *key);

bool
hsk_map_del(hsk_map_t *map, void *key);

uint32_t
hsk_map_hash_str(void *key);

bool
hsk_map_equal_str(void *a, void *b);

uint32_t
hsk_map_hash_int(void *key);

bool
hsk_map_equal_int(void *a, void *b);

uint32_t
hsk_map_hash_hash(void *key);

bool
hsk_map_equal_hash(void *a, void *b);
#endif
