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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "map.h"

void
hsk_map_init(
  hsk_map_t *map,
  bool is_map,
  hsk_map_hash_func hash_func,
  hsk_map_equal_func equal_func,
  hsk_map_free_func free_func
) {
  memset(map, 0, sizeof(hsk_map_t));
  map->is_map = is_map;
  map->hash_func = hash_func;
  map->equal_func = equal_func;
  map->free_func = free_func;
}

void
hsk_map_init_map(
  hsk_map_t *map,
  hsk_map_hash_func hash_func,
  hsk_map_equal_func equal_func,
  hsk_map_free_func free_func
) {
  hsk_map_init(map, true, hash_func, equal_func, free_func);
}

void
hsk_map_init_set(
  hsk_map_t *map,
  hsk_map_hash_func hash_func,
  hsk_map_equal_func equal_func
) {
  hsk_map_init(map, false, hash_func, equal_func, NULL);
}

void
hsk_map_init_hash_map(hsk_map_t *map, hsk_map_free_func free_func) {
  hsk_map_init_map(map, hsk_map_hash_hash, hsk_map_equal_hash, free_func);
}

void
hsk_map_init_hash_set(hsk_map_t *map) {
  hsk_map_init_set(map, hsk_map_hash_hash, hsk_map_equal_hash);
}

void
hsk_map_init_str_map(hsk_map_t *map, hsk_map_free_func free_func) {
  hsk_map_init_map(map, hsk_map_hash_str, hsk_map_equal_str, free_func);
}

void
hsk_map_init_str_set(hsk_map_t *map) {
  hsk_map_init_set(map, hsk_map_hash_str, hsk_map_equal_str);
}

void
hsk_map_init_int_map(hsk_map_t *map, hsk_map_free_func free_func) {
  hsk_map_init_map(map, hsk_map_hash_int, hsk_map_equal_int, free_func);
}

void
hsk_map_init_int_set(hsk_map_t *map) {
  hsk_map_init_set(map, hsk_map_hash_int, hsk_map_equal_int);
}

void
hsk_map_uninit(hsk_map_t *map) {
  if (!map)
    return;

  hsk_map_clear(map);

  if (map->keys) {
    free(map->keys);
    map->keys = NULL;
  }

  if (map->flags) {
    free(map->flags);
    map->flags = NULL;
  }

  if (map->vals) {
    free(map->vals);
    map->vals = NULL;
  }
}

hsk_map_t *
hsk_map_alloc(
  bool is_map,
  hsk_map_hash_func hash_func,
  hsk_map_equal_func equal_func,
  hsk_map_free_func free_func
) {
  hsk_map_t *map = (hsk_map_t *)malloc(sizeof(hsk_map_t));
  hsk_map_init(map, is_map, hash_func, equal_func, free_func);
  return map;
}

hsk_map_t *
hsk_map_alloc_map(
  hsk_map_hash_func hash_func,
  hsk_map_equal_func equal_func,
  hsk_map_free_func free_func
) {
  hsk_map_t *map = (hsk_map_t *)malloc(sizeof(hsk_map_t));
  hsk_map_init_map(map, hash_func, equal_func, free_func);
  return map;
}

hsk_map_t *
hsk_map_alloc_set(
  hsk_map_hash_func hash_func,
  hsk_map_equal_func equal_func
) {
  hsk_map_t *map = (hsk_map_t *)malloc(sizeof(hsk_map_t));
  hsk_map_init_set(map, hash_func, equal_func);
  return map;
}

hsk_map_t *
hsk_map_alloc_hash_map(hsk_map_free_func free_func) {
  return hsk_map_alloc_map(hsk_map_hash_hash, hsk_map_equal_hash, free_func);
}

hsk_map_t *
hsk_map_alloc_hash_set(void) {
  return hsk_map_alloc_set(hsk_map_hash_hash, hsk_map_equal_hash);
}

hsk_map_t *
hsk_map_alloc_str_map(hsk_map_free_func free_func) {
  return hsk_map_alloc_map(hsk_map_hash_str, hsk_map_equal_str, free_func);
}

hsk_map_t *
hsk_map_alloc_str_set(void) {
  return hsk_map_alloc_set(hsk_map_hash_str, hsk_map_equal_str);
}

hsk_map_t *
hsk_map_alloc_int_map(hsk_map_free_func free_func) {
  return hsk_map_alloc_map(hsk_map_hash_int, hsk_map_equal_int, free_func);
}

hsk_map_t *
hsk_map_alloc_int_set(void) {
  return hsk_map_alloc_set(hsk_map_hash_int, hsk_map_equal_int);
}

void
hsk_map_free(hsk_map_t *map) {
  if (!map)
    return;

  hsk_map_uninit(map);
  free(map);
}

void
hsk_map_reset(hsk_map_t *map) {
  if (map && map->flags) {
    memset(map->flags, 0xaa,
      __hsk_fsize(map->n_buckets) * sizeof(uint32_t));

    map->size = 0;
    map->n_occupied = 0;
  }
}

uint32_t
hsk_map_lookup(const hsk_map_t *map, const void *key) {
  if (map->n_buckets == 0)
    return 0;

  uint32_t step = 0;
  uint32_t mask = map->n_buckets - 1;
  uint32_t k = map->hash_func(key);
  uint32_t i = k & mask;
  uint32_t last = i;

  while (!__hsk_isempty(map->flags, i)
         && (__hsk_isdel(map->flags, i)
         || !map->equal_func(map->keys[i], key))) {
    i = (i + (++step)) & mask;

    if (i == last)
      return map->n_buckets;
  }

  return __hsk_iseither(map->flags, i) ? map->n_buckets : i;
}

int
hsk_map_resize(hsk_map_t *map, uint32_t new_n_buckets) {
  // This function uses 0.25*n_buckets bytes of working space
  // instead of [sizeof(key_t+val_t)+.25]*n_buckets.

  uint32_t *new_flags = 0;
  uint32_t j = 1;

  {
    __hsk_roundup32(new_n_buckets);

    if (new_n_buckets < 4)
      new_n_buckets = 4;

    if (map->size >= (uint32_t)(new_n_buckets * __hsk_hash_upper + 0.5)) {
      // requested size is too small
      j = 0;
    } else {
      // hash table size to be changed (shrink or expand); rehash
      new_flags = (uint32_t *)malloc(
        __hsk_fsize(new_n_buckets) * sizeof(uint32_t));

      if (!new_flags)
        return -1;

      memset(new_flags, 0xaa,
        __hsk_fsize(new_n_buckets) * sizeof(uint32_t));

      if (map->n_buckets < new_n_buckets) {  /* expand */
        void **new_keys = (void **)realloc(
          map->keys, new_n_buckets * sizeof(void *));

        if (!new_keys) {
          free(new_flags);
          return -1;
        }

        map->keys = new_keys;

        if (map->is_map) {
          void **new_vals = (void **)realloc(
            (void *)map->vals, new_n_buckets * sizeof(void *));

          if (!new_vals) {
            free(new_flags);
            return -1;
          }

          map->vals = new_vals;
        }
      }
      // otherwise shrink
    }
  }

  if (j) {
    // rehashing is needed
    for (j = 0; j < map->n_buckets; j++) {
      if (__hsk_iseither(map->flags, j) == 0) {
        uint32_t new_mask = new_n_buckets - 1;
        void *key = map->keys[j];
        void *val = NULL;

        if (map->is_map)
          val = map->vals[j];

        __hsk_set_isdel_true(map->flags, j);

        // kick-out process; sort of like in cuckoo hashing
        for (;;) {
          uint32_t k = map->hash_func(key);
          uint32_t i = k & new_mask;
          uint32_t step = 0;

          while (!__hsk_isempty(new_flags, i))
            i = (i + (++step)) & new_mask;

          __hsk_set_isempty_false(new_flags, i);

          // kick out the existing element
          if (i < map->n_buckets && __hsk_iseither(map->flags, i) == 0) {
            {
              void *tmp = map->keys[i];
              map->keys[i] = key;
              key = tmp;
            }

            if (map->is_map) {
              void *tmp = map->vals[i];
              map->vals[i] = val;
              val = tmp;
            }

            // mark it as deleted in the old hash table
            __hsk_set_isdel_true(map->flags, i);
          } else {
            // write the element and jump out of the loop
            map->keys[i] = key;
            if (map->is_map)
              map->vals[i] = val;
            break;
          }
        }
      }
    }

    // shrink the hash table
    if (map->n_buckets > new_n_buckets) {
      map->keys = (void **)realloc(
        (void *)map->keys, new_n_buckets * sizeof(void *));

      if (map->is_map) {
        map->vals = (void **)realloc(
          (void *)map->vals, new_n_buckets * sizeof(void *));
      }
    }

    // free the working space
    free(map->flags);
    map->flags = new_flags;
    map->n_buckets = new_n_buckets;
    map->n_occupied = map->size;
    map->upper_bound = (uint32_t)(map->n_buckets * __hsk_hash_upper + 0.5);
  }

  return 0;
}

uint32_t
hsk_map_put(hsk_map_t *map, void *key, int *ret) {
  uint32_t x;

  // update the hash table
  if (map->n_occupied >= map->upper_bound) {
    if (map->n_buckets > (map->size << 1)) {
      // clear "deleted" elements
      if (hsk_map_resize(map, map->n_buckets - 1) < 0) {
        if (ret)
          *ret = -1;
        return map->n_buckets;
      }
    } else if (hsk_map_resize(map, map->n_buckets + 1) < 0) {
      // expand the hash table
      if (ret)
        *ret = -1;
      return map->n_buckets;
    }
  }

  // TODO: to implement automatically shrinking
  // resize() already support shrinking

  {
    uint32_t mask = map->n_buckets - 1;
    uint32_t step = 0;
    uint32_t site = map->n_buckets;
    uint32_t k = map->hash_func(key);
    uint32_t i = k & mask;
    uint32_t last;

    x = map->n_buckets;

    if (__hsk_isempty(map->flags, i)) {
      // for speed up
      x = i;
    } else {
      last = i;

      while (!__hsk_isempty(map->flags, i)
             && (__hsk_isdel(map->flags, i)
             || !map->equal_func(map->keys[i], key))) {
        if (__hsk_isdel(map->flags, i))
          site = i;

        i = (i + (++step)) & mask;

        if (i == last) {
          x = site;
          break;
        }
      }

      if (x == map->n_buckets) {
        if (__hsk_isempty(map->flags, i) && site != map->n_buckets)
          x = site;
        else
          x = i;
      }
    }
  }

  if (__hsk_isempty(map->flags, x)) {
    // not present at all
    map->keys[x] = key;
    __hsk_set_isboth_false(map->flags, x);
    map->size += 1;
    map->n_occupied += 1;
    if (ret)
      *ret = 1;
  } else if (__hsk_isdel(map->flags, x)) {
    // deleted
    map->keys[x] = key;
    __hsk_set_isboth_false(map->flags, x);
    map->size += 1;
    if (ret)
      *ret = 2;
  } else {
    // present and not deleted
    map->keys[x] = key;
    if (ret)
      *ret = 0;
  }

  return x;
}

void
hsk_map_delete(hsk_map_t *map, uint32_t x) {
  if (x != map->n_buckets && !__hsk_iseither(map->flags, x)) {
    __hsk_set_isdel_true(map->flags, x);
    map->size -= 1;
  }
}

void
hsk_map_clear(hsk_map_t *map) {
  if (map->is_map && map->free_func) {
    uint32_t k;

    for (k = 0; k < map->n_buckets; k++) {
      if (!hsk_map_exists(map, k))
        continue;

      void *value = map->vals[k];

      if (value)
        map->free_func(value);
    }
  }

  hsk_map_reset(map);
}

bool
hsk_map_set(hsk_map_t *map, void *key, void *value) {
  int ret;
  uint32_t k = hsk_map_put(map, key, &ret);

  if (ret == -1)
    return false;

  map->vals[k] = value;

  return true;
}

void *
hsk_map_get(const hsk_map_t *map, const void *key) {
  uint32_t k = hsk_map_lookup(map, key);

  if (k == map->n_buckets)
    return NULL;

  if (!hsk_map_exists(map, k))
    return NULL;

  return map->vals[k];
}

bool
hsk_map_has(const hsk_map_t *map, const void *key) {
  uint32_t k = hsk_map_lookup(map, key);

  if (k == map->n_buckets)
    return false;

  if (!hsk_map_exists(map, k))
    return false;

  return true;
}

bool
hsk_map_del(hsk_map_t *map, const void *key) {
  uint32_t k = hsk_map_lookup(map, key);

  if (k == map->n_buckets)
    return false;

  if (!hsk_map_exists(map, k))
    return false;

  hsk_map_delete(map, k);

  return true;
}

uint32_t
hsk_map_hash_str(const void *key) {
  char *s = (char *)key;

  uint32_t hash = 5381;

  for (; *s; s++)
    hash = ((hash << 5) + hash) + ((uint32_t)*s);

  return hash;
}

bool
hsk_map_equal_str(const void *a, const void *b) {
  return strcmp((const char *)a, (const char *)b) == 0;
}

uint32_t
hsk_map_hash_int(const void *key) {
  uint32_t hash = *((uint32_t *)key);
  hash += ~(hash << 15);
  hash ^= (hash >> 10);
  hash += (hash << 3);
  hash ^= (hash >> 6);
  hash += ~(hash << 11);
  hash ^= (hash >> 16);
  return hash;
}

bool
hsk_map_equal_int(const void *a, const void *b) {
  return *((uint32_t *)a) == *((uint32_t *)b);
}

uint32_t
hsk_map_hash_hash(const void *key) {
  const uint8_t *data = (const uint8_t *)key;
  return hsk_map_murmur3(data, 32, 0xfba4c795);
}

bool
hsk_map_equal_hash(const void *a, const void *b) {
  return memcmp(a, b, 32) == 0;
}

uint32_t
hsk_map_murmur3(const uint8_t *data, size_t data_len, uint32_t seed) {
  const uint32_t c1 = 0xcc9e2d51;
  const uint32_t c2 = 0x1b873593;

  int tail = data_len - (data_len % 4);
  int i;

  uint32_t h1 = seed;
  uint32_t k1;

#define __h_rotl32(w, b) ((w << b) | (w >> (32 - b)))

  for (i = 0; i < tail; i += 4) {
    k1 = (data[i + 3] << 24)
      | (data[i + 2] << 16)
      | (data[i + 1] << 8)
      | data[i];
    k1 = k1 * c1;
    k1 = __h_rotl32(k1, 15);
    k1 = k1 * c2;
    h1 ^= k1;
    h1 = __h_rotl32(h1, 13);
    h1 = (h1 * 5) + 0xe6546b64;
  }

  k1 = 0;

  switch (data_len & 3) {
    case 3:
      k1 ^= data[tail + 2] << 16;
    case 2:
      k1 ^= data[tail + 1] << 8;
    case 1:
      k1 ^= data[tail + 0];
      k1 = k1 * c1;
      k1 = __h_rotl32(k1, 15);
      k1 = k1 * c2;
      h1 ^= k1;
  }

#undef __h_rotl32

  h1 ^= data_len;
  h1 ^= h1 >> 16;
  h1 = h1 * 0x85ebca6b;
  h1 ^= h1 >> 13;
  h1 = h1 * 0xc2b2ae35;
  h1 ^= h1 >> 16;

  return h1;
}

uint32_t
hsk_map_tweak3(
  const uint8_t *data,
  size_t data_len,
  uint32_t n,
  uint32_t tweak
) {
  uint32_t seed = (n * 0xfba4c795) + tweak;
  return hsk_map_murmur3(data, data_len, seed);
}
