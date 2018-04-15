#ifndef _HSK_ADDRMGR_H
#define _HSK_ADDRMGR_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "addr.h"
#include "timedata.h"
#include "map.h"

typedef struct hsk_addrentry_s {
  hsk_addr_t addr;
  uint64_t time;
  uint64_t services;
  int32_t attempts;
  int64_t last_success;
  int64_t last_attempt;
  int32_t ref_count;
  bool used;
  bool removed;
} hsk_addrentry_t;

typedef struct hsk_banned_t {
  hsk_addr_t addr;
  uint16_t port;
  int64_t time;
} hsk_banned_t;

typedef struct hsk_addrman_s {
  hsk_timedata_t *td;
  size_t size;
  hsk_addrentry_t *addrs;
  hsk_map_t map;
  hsk_map_t banned;
} hsk_addrman_t;

int32_t
hsk_addrman_init(hsk_addrman_t *am, const hsk_timedata_t *td);

void
hsk_addrman_uninit(hsk_addrman_t *am);

hsk_addrman_t *
hsk_addrman_alloc(const hsk_timedata_t *td);

void
hsk_addrman_free(hsk_addrman_t *am);

hsk_addrentry_t *
hsk_addrman_alloc_entry(hsk_addrman_t *am, bool *alloc);

const hsk_addrentry_t *
hsk_addrman_get(const hsk_addrman_t *am, const hsk_addr_t *addr);

bool
hsk_addrman_add_entry(hsk_addrman_t *am, const hsk_netaddr_t *na, bool src);

bool
hsk_addrman_add_addr(hsk_addrman_t *am, const hsk_addr_t *addr);

bool
hsk_addrman_add_na(hsk_addrman_t *am, const hsk_netaddr_t *na);

bool
hsk_addrman_add_sa(hsk_addrman_t *am, const struct sockaddr *sa);

bool
hsk_addrman_add_ip(
  hsk_addrman_t *am,
  int32_t af,
  const uint8_t *ip,
  uint16_t port
);

bool
hsk_addrman_remove_addr(hsk_addrman_t *am, const hsk_addr_t *addr);

bool
hsk_addrman_mark_attempt(hsk_addrman_t *am, const hsk_addr_t *addr);

bool
hsk_addrman_mark_success(hsk_addrman_t *am, const hsk_addr_t *addr);

bool
hsk_addrman_mark_ack(
  hsk_addrman_t *am,
  const hsk_addr_t *addr,
  uint64_t services
);

void
hsk_addrman_clear_banned(hsk_addrman_t *am);

bool
hsk_addrman_add_ban(hsk_addrman_t *am, const hsk_addr_t *addr);

bool
hsk_addrman_is_banned(hsk_addrman_t *am, const hsk_addr_t *addr);

const hsk_addrentry_t *
hsk_addrman_pick(hsk_addrman_t *am, const hsk_map_t *map);

bool
hsk_addrman_pick_addr(
  hsk_addrman_t *am,
  const hsk_map_t *map,
  hsk_addr_t *addr
);

bool
hsk_addrman_pick_sa(
  hsk_addrman_t *am,
  const hsk_map_t *map,
  struct sockaddr *sa
);
#endif
