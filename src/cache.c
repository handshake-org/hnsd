#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "cache.h"
#include "dns.h"
#include "error.h"
#include "map.h"
#include "req.h"
#include "resource.h"
#include "utils.h"

void
hsk_cache_init(hsk_cache_t *c) {
  assert(c);
  hsk_map_init_map(&c->map,
    hsk_cache_key_hash,
    hsk_cache_key_equal,
    (hsk_map_free_func)hsk_cache_item_free);
}

void
hsk_cache_uninit(hsk_cache_t *c) {
  assert(c);
  hsk_map_uninit(&c->map);
}

hsk_cache_t *
hsk_cache_alloc(void) {
  hsk_cache_t *c = malloc(sizeof(hsk_cache_t));
  if (c)
    hsk_cache_init(c);
  return c;
}

void
hsk_cache_free(hsk_cache_t *c) {
  assert(c);
  hsk_cache_uninit(c);
  free(c);
}

static void
hsk_cache_log(const hsk_cache_t *c, const char *fmt, ...) {
  assert(c);
  printf("cache: ");

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

static void
hsk_cache_prune(hsk_cache_t *c) {
  assert(c);
  hsk_map_clear(&c->map);
}

bool
hsk_cache_insert_data(
  hsk_cache_t *c,
  const uint8_t *name,
  uint16_t type,
  uint8_t *wire,
  size_t wire_len
) {
  assert(c);

  hsk_cache_key_t ck;
  hsk_cache_key_init(&ck);

  if (!hsk_cache_key_set(&ck, name, type))
    return false;

  hsk_cache_item_t *cache = hsk_map_get(&c->map, &ck);

  if (cache) {
    if (hsk_now() < cache->time + 6 * 60 * 60) {
      free(wire);
      return true;
    }

    hsk_map_del(&c->map, &ck);
    hsk_cache_item_free(cache);

    cache = NULL;
  }

  if (c->map.size >= HSK_CACHE_LIMIT)
    hsk_cache_prune(c);

  hsk_cache_item_t *item = hsk_cache_item_alloc();

  if (!item)
    return false;

  memcpy(&item->key, &ck, sizeof(hsk_cache_key_t));

  item->msg = wire;
  item->msg_len = wire_len;
  item->time = hsk_now();

  if (!hsk_map_set(&c->map, &item->key, item)) {
    // hsk_cache_insert will free msg on false
    item->msg = NULL;
    free(item);
    return false;
  }

  return true;
}

bool
hsk_cache_insert(
  hsk_cache_t *c,
  const hsk_dns_req_t *req,
  const hsk_dns_msg_t *msg
) {
  uint8_t *wire;
  size_t wire_len;

  if (!hsk_dns_msg_encode(msg, &wire, &wire_len)) {
    hsk_cache_log(c, "could not encode cache\n");
    return false;
  }

  if (!hsk_cache_insert_data(c, req->name, req->type, wire, wire_len)) {
    hsk_cache_log(c, "could not insert cache\n");
    free(wire);
    return false;
  }

  return true;
}

bool
hsk_cache_get_data(
  hsk_cache_t *c,
  const uint8_t *name,
  uint16_t type,
  uint8_t **wire,
  size_t *wire_len
) {
  assert(c && name && wire);

  hsk_cache_key_t ck;
  hsk_cache_key_init(&ck);

  if (!hsk_cache_key_set(&ck, name, type))
    return false;

  hsk_cache_item_t *cache = hsk_map_get(&c->map, &ck);

  if (!cache)
    return false;

  if (hsk_now() >= cache->time + 6 * 60 * 60) {
    hsk_map_del(&c->map, &ck);
    hsk_cache_item_free(cache);
    return false;
  }

  *wire = cache->msg;
  *wire_len = cache->msg_len;

  return true;
}

hsk_dns_msg_t *
hsk_cache_get(hsk_cache_t *c, const hsk_dns_req_t *req) {
  uint8_t *data;
  size_t data_len;
  hsk_dns_msg_t *msg;

  if (!hsk_cache_get_data(c, req->name, req->type, &data, &data_len))
    return NULL;

  char namestr[HSK_DNS_MAX_NAME_STRING] = {0};
  assert(hsk_dns_name_to_string(req->name, namestr));
  hsk_cache_log(c, "cache hit for: %s\n", namestr);

  if (!hsk_dns_msg_decode(data, data_len, &msg)) {
    hsk_cache_log(c, "could not deserialize cached item\n");
    return NULL;
  }

  return msg;
}

void
hsk_cache_key_init(hsk_cache_key_t *ck) {
  assert(ck);
  memset(&ck->name[0], 0, sizeof(ck->name));
  ck->name_len = 0;
  ck->ref = false;
  ck->type = 0;
}

void
hsk_cache_key_uninit(hsk_cache_key_t *ck) {
  assert(ck);
}

hsk_cache_key_t *
hsk_cache_key_alloc(void) {
  hsk_cache_key_t *ck = malloc(sizeof(hsk_cache_key_t));
  if (ck)
    hsk_cache_key_init(ck);
  return ck;
}

void
hsk_cache_key_free(hsk_cache_key_t *ck) {
  assert(ck);
  hsk_cache_key_uninit(ck);
  free(ck);
}

uint32_t
hsk_cache_key_hash(const void *key) {
  hsk_cache_key_t *ck = (hsk_cache_key_t *)key;
  assert(ck);
  // Ignore type if referral.
  if (ck->ref)
    return hsk_map_tweak3(ck->name, ck->name_len, 2, 1);
  return hsk_map_tweak3(ck->name, ck->name_len, 1, ck->type);
}

bool
hsk_cache_key_equal(const void *a, const void *b) {
  assert(a && b);

  hsk_cache_key_t *x = (hsk_cache_key_t *)a;
  hsk_cache_key_t *y = (hsk_cache_key_t *)b;

  if (x->ref != y->ref)
    return false;

  // Ignore type if referral.
  if (!x->ref) {
    if (x->type != y->type)
      return false;
  }

  if (x->name_len != y->name_len)
    return false;

  if (memcmp(x->name, y->name, x->name_len) != 0)
    return false;

  return true;
}

bool
hsk_cache_key_set(hsk_cache_key_t *ck, const uint8_t *name, uint16_t type) {
  assert(ck);

  int labels = hsk_dns_label_count(name);
  bool ref = false;

  switch (labels) {
    case 0:
    case 1:
      ref = false;
      break;
    case 2:
      ref = !hsk_resource_is_ptr(name);
      break;
    default:
      ref = true;
      break;
  }

  if (ref)
    labels = 1;

  ck->name_len = hsk_dns_label_from(name, -labels, ck->name);
  hsk_to_lower(ck->name);
  ck->ref = ref;
  ck->type = type;

  return true;
}

void
hsk_cache_item_init(hsk_cache_item_t *ci) {
  assert(ci);
  hsk_cache_key_init(&ci->key);
  ci->msg = NULL;
  ci->msg_len = 0;
  ci->time = 0;
}

void
hsk_cache_item_uninit(hsk_cache_item_t *ci) {
  assert(ci);
  if (ci->msg) {
    free(ci->msg);
    ci->msg = NULL;
    ci->msg_len = 0;
  }
}

hsk_cache_item_t *
hsk_cache_item_alloc(void) {
  hsk_cache_item_t *ci = malloc(sizeof(hsk_cache_item_t));
  if (ci)
    hsk_cache_item_init(ci);
  return ci;
}

void
hsk_cache_item_free(hsk_cache_item_t *ci) {
  assert(ci);
  hsk_cache_item_uninit(ci);
  free(ci);
}
