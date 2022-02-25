#ifndef _HSK_CACHE_H
#define _HSK_CACHE_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include "dns.h"
#include "map.h"
#include "req.h"

#define HSK_CACHE_LIMIT 2000

typedef struct hsk_cache_s {
  hsk_map_t map;
} hsk_cache_t;

typedef struct hsk_cache_key_s {
  uint8_t name[HSK_DNS_MAX_NAME];
  size_t name_len;
  uint16_t type;
  bool ref;
} hsk_cache_key_t;

typedef struct hsk_cache_item_s {
  hsk_cache_key_t key;
  uint8_t *msg;
  size_t msg_len;
  int64_t time;
} hsk_cache_item_t;

void
hsk_cache_init(hsk_cache_t *c);

void
hsk_cache_uninit(hsk_cache_t *c);

hsk_cache_t *
hsk_cache_alloc(void);

void
hsk_cache_free(hsk_cache_t *c);

bool
hsk_cache_insert_data(
  hsk_cache_t *c,
  const uint8_t *name,
  uint16_t type,
  uint8_t *wire,
  size_t wire_len
);

bool
hsk_cache_insert(
  hsk_cache_t *c,
  const hsk_dns_req_t *req,
  const hsk_dns_msg_t *msg
);

bool
hsk_cache_get_data(
  hsk_cache_t *c,
  const uint8_t *name,
  uint16_t type,
  uint8_t **wire,
  size_t *wire_len
);

hsk_dns_msg_t *
hsk_cache_get(hsk_cache_t *c, const hsk_dns_req_t *req);

void
hsk_cache_key_init(hsk_cache_key_t *ck);

void
hsk_cache_key_uninit(hsk_cache_key_t *ck);

hsk_cache_key_t *
hsk_cache_key_alloc(void);

void
hsk_cache_key_free(hsk_cache_key_t *ck);

uint32_t
hsk_cache_key_hash(const void *key);

bool
hsk_cache_key_equal(const void *a, const void *b);

bool
hsk_cache_key_set(hsk_cache_key_t *ck, const uint8_t *name, uint16_t type);

void
hsk_cache_item_init(hsk_cache_item_t *ci);

void
hsk_cache_item_uninit(hsk_cache_item_t *ci);

hsk_cache_item_t *
hsk_cache_item_alloc(void);

void
hsk_cache_item_free(hsk_cache_item_t *ci);
#endif
