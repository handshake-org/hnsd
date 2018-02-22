#include "map.h"

hash_map_t *
hash_map_alloc(void) {
  return kh_init(HASH256);
}

void
hash_map_free(hash_map_t *map) {
  kh_destroy(HASH256, map);
}

int32_t
hash_map_set(hash_map_t *map, uint8_t *key, void *hdr) {
  int32_t ret;

  khiter_t k = kh_put(HASH256, map, key, &ret);

  if (ret == -1)
    return ret;

  kh_value(map, k) = hdr;

  return ret == 0 ? 1 : 0;
}

void *
hash_map_get(hash_map_t *map, uint8_t *key) {
  khiter_t k = kh_get(HASH256, map, key);

  if (k == kh_end(map))
    return NULL;

  return kh_value(map, k);
}

bool
hash_map_has(hash_map_t *map, uint8_t *key) {
  khiter_t k = kh_get(HASH256, map, key);

  if (k == kh_end(map))
    return false;

  return kh_exist(map, k) == 1;
}

bool
hash_map_del(hash_map_t *map, uint8_t *key) {
  khiter_t k = kh_get(HASH256, map, key);

  if (k == kh_end(map))
    return false;

  kh_del(HASH256, map, k);

  return true;
}

int_map_t *
int_map_alloc(void) {
  return kh_init(HEIGHT);
}

void
int_map_free(int_map_t *map) {
  kh_destroy(HEIGHT, map);
}

int32_t
int_map_set(int_map_t *map, uint32_t key, void *hdr) {
  int32_t ret;

  khiter_t k = kh_put(HEIGHT, map, (int32_t)key, &ret);

  if (ret == -1)
    return ret;

  kh_value(map, k) = hdr;

  return ret == 0 ? 1 : 0;
}

void *
int_map_get(int_map_t *map, uint32_t key) {
  khiter_t k = kh_get(HEIGHT, map, (int32_t)key);

  if (k == kh_end(map))
    return NULL;

  return kh_value(map, k);
}

bool
int_map_has(int_map_t *map, uint32_t key) {
  khiter_t k = kh_get(HEIGHT, map, (int32_t)key);

  if (k == kh_end(map))
    return false;

  return kh_exist(map, k) == 1;
}

bool
int_map_del(int_map_t *map, uint32_t key) {
  khiter_t k = kh_get(HEIGHT, map, (int32_t)key);

  if (k == kh_end(map))
    return false;

  kh_del(HEIGHT, map, k);

  return true;
}
