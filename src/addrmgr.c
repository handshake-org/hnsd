#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <math.h>

#include "hsk-addr.h"
#include "hsk-addrmgr.h"
#include "hsk-constants.h"
#include "hsk-error.h"
#include "hsk-map.h"
#include "hsk-msg.h"
#include "hsk-timedata.h"
#include "utils.h"

#define HSK_ADDR_MAX 2000
#define HSK_HORIZON_DAYS 30
#define HSK_RETRIES 3
#define HSK_MIN_FAIL_DAYS 7
#define HSK_MAX_FAILURES 10
#define HSK_MAX_REFS 8
#define HSK_BAN_TIME 24 * 60 * 60

#define max(x, y) (((x) > (y)) ? (x) : (y))
#define min(x, y) (((x) < (y)) ? (x) : (y))

static const uint8_t hsk_ipv6_mapped[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0xff, 0xff
};

static bool
hsk_ip_type(uint8_t *ip) {
  if (memcmp(ip, hsk_ipv6_mapped, 12) == 0)
    return AF_INET;

  return AF_INET6;
}

static bool
hsk_addrman_is_stale(hsk_addrman_t *am, hsk_addrentry_t *);

static double
hsk_addrentry_chance(hsk_addrentry_t *, int64_t);

int32_t
hsk_addrman_init(hsk_addrman_t *am, hsk_timedata_t *td) {
  if (!am || !td)
    return HSK_EBADARGS;

  int32_t rc = HSK_SUCCESS;
  hsk_addrentry_t **addrs = NULL;

  addrs = (hsk_addrentry_t **)calloc(1, sizeof(hsk_addrentry_t) * HSK_ADDR_MAX);

  if (!addrs) {
    rc = HSK_ENOMEM;
    goto fail;
  }

  am->td = td;
  am->addrs = addrs;
  am->size = 0;
  hsk_map_init_map(&am->map, hsk_addr_hash, hsk_addr_equal, NULL);
  hsk_map_init_map(&am->banned, hsk_addr_hash, hsk_addr_equal, free);

  return rc;

fail:
  if (addrs)
    free(addrs);

  return rc;
}

void
hsk_addrman_uninit(hsk_addrman_t *am) {
  if (!am)
    return;

  free(am->addrs);
  hsk_map_uninit(&am->map);
  hsk_map_uninit(&am->banned);
}

hsk_addrman_t *
hsk_addrman_alloc(hsk_timedata_t *td) {
  hsk_addrman_t *am = malloc(sizeof(hsk_addrman_t));
  hsk_addrman_init(am, td);
  return am;
}

void
hsk_addrman_free(hsk_addrman_t *am) {
  if (!am)
    return;

  hsk_addrman_uninit(am);
  free(am);
}

hsk_addrentry_t *
hsk_addrman_alloc_entry(hsk_addrman_t *am) {
  if (am->size == HSK_ADDR_MAX)
    return NULL;
  assert(am->size < HSK_ADDR_MAX);
  return am->addrs[am->size];
}

bool
hsk_addrman_add_entry(hsk_addrman_t *am, hsk_addrentry_t *addr, bool src) {
  hsk_addrentry_t *entry = hsk_map_get(&am->map, addr);

  if (entry) {
    int32_t penalty = 2 * 60 * 60;
    int32_t interval = 24 * 60 * 60;

    // No source means we're inserting
    // this ourselves. No penalty.
    if (!src)
      penalty = 0;

    // Update services.
    entry->services |= addr->services;

    // Online?
    int64_t now = hsk_timedata_now(am->td);
    if (now - addr->time < 24 * 60 * 60)
      interval = 60 * 60;

    // Periodically update time.
    if (entry->time < addr->time - interval - penalty)
      entry->time = addr->time;

    // Do not update if no new
    // information is present.
    if (entry->time && addr->time <= entry->time)
      return false;

    // Do not update if the entry was
    // already in the "used" table.
    if (entry->used)
      return false;

    assert(entry->ref_count > 0);

    // Do not update if the max
    // reference count is reached.
    if (entry->ref_count == HSK_MAX_REFS)
      return false;

    assert(entry->ref_count < HSK_MAX_REFS);

    // Stochastic test: previous refCount
    // N: 2^N times harder to increase it.
    int32_t factor = 1;
    int32_t i;
    for (i = 0; i < entry->ref_count; i++)
      factor *= 2;

    if ((hsk_random() % factor) != 0)
      return false;

    entry->ref_count += 1;
  } else {
    if (am->size + 1 == HSK_ADDR_MAX)
      return false;

    if (!hsk_map_set(&am->map, addr, addr))
      return false;

    am->size += 1;
  }

  return true;
}

bool
hsk_addrman_add_addr(hsk_addrman_t *am, hsk_addr_t *addr) {
  hsk_addrentry_t *entry = hsk_addrman_alloc_entry(am);

  if (!entry)
    return false;

  if (!hsk_addr_is_valid(addr))
    return false;

  hsk_addr_copy((hsk_addr_t *)entry, addr);

  entry->time = hsk_timedata_now(am->td);
  entry->services = 1;
  entry->attempts = 0;
  entry->last_success = 0;
  entry->last_attempt = 0;
  entry->ref_count = 0;
  entry->used = false;

  return hsk_addrman_add_entry(am, entry, false);
}

bool
hsk_addrman_add_na(hsk_addrman_t *am, hsk_netaddr_t *addr) {
  hsk_addrentry_t *entry = hsk_addrman_alloc_entry(am);

  if (!entry)
    return false;

  if (!hsk_addr_from_na((hsk_addr_t *)entry, addr))
    return false;

  entry->time = addr->time;
  entry->services = addr->services;
  entry->attempts = 0;
  entry->last_success = 0;
  entry->last_attempt = 0;
  entry->ref_count = 0;
  entry->used = false;

  return hsk_addrman_add_entry(am, entry, true);
}

int32_t
hsk_addrman_add_sa(hsk_addrman_t *am, struct sockaddr *addr) {
  hsk_addrentry_t *entry = hsk_addrman_alloc_entry(am);

  if (!entry)
    return false;

  if (!hsk_addr_from_sa((hsk_addr_t *)entry, addr))
    return false;

  entry->time = hsk_timedata_now(am->td);
  entry->services = 1;
  entry->attempts = 0;
  entry->last_success = 0;
  entry->last_attempt = 0;
  entry->ref_count = 0;
  entry->used = false;

  return hsk_addrman_add_entry(am, entry, false);
}

int32_t
hsk_addrman_add_ip(hsk_addrman_t *am, int32_t af, uint8_t *ip, uint16_t port) {
  hsk_addrentry_t *entry = hsk_addrman_alloc_entry(am);

  if (!entry)
    return false;

  if (!hsk_addr_from_ip((hsk_addr_t *)entry, af, ip, port))
    return false;

  entry->time = hsk_timedata_now(am->td);
  entry->services = 1;
  entry->attempts = 0;
  entry->last_success = 0;
  entry->last_attempt = 0;
  entry->ref_count = 0;
  entry->used = false;

  return hsk_addrman_add_entry(am, entry, false);
}

bool
hsk_addrman_mark_attempt(hsk_addrman_t *am, hsk_addr_t *addr) {
  hsk_addrentry_t *entry = hsk_map_get(&am->map, addr);

  if (!entry)
    return false;

  entry->attempts += 1;
  entry->last_attempt = hsk_timedata_now(am->td);

  return true;
}

bool
hsk_addrman_mark_success(hsk_addrman_t *am, hsk_addr_t *addr) {
  hsk_addrentry_t *entry = hsk_map_get(&am->map, addr);

  if (!entry)
    return false;

  int64_t now = hsk_timedata_now(am->td);

  if (now - entry->time > 20 * 60) {
    entry->time = now;
    return true;
  }

  return false;
}

bool
hsk_addrman_mark_ack(hsk_addrman_t *am, hsk_addr_t *addr, uint64_t services) {
  hsk_addrentry_t *entry = hsk_map_get(&am->map, addr);

  if (!entry)
    return false;

  int64_t now = hsk_timedata_now(am->td);

  entry->services |= services;

  entry->last_success = now;
  entry->last_attempt = now;
  entry->attempts = 0;
  entry->used = true;

  return true;
}

void
hsk_addrman_clear_banned(hsk_addrman_t *am) {
  hsk_map_clear(&am->banned);
}

bool
hsk_addrman_add_ban(hsk_addrman_t *am, hsk_addr_t *addr) {
  hsk_banned_t *entry = hsk_map_get(&am->banned, addr);

  int64_t now = hsk_timedata_now(am->td);

  if (entry) {
    entry->time = now;
    return true;
  }

  hsk_banned_t *ban = malloc(sizeof(hsk_banned_t));

  if (!ban)
    return false;

  hsk_addr_copy((hsk_addr_t *)ban, addr);
  ban->time = now;

  if (!hsk_map_set(&am->banned, ban, ban)) {
    free(ban);
    return false;
  }

  return true;
}

bool
hsk_addrman_is_banned(hsk_addrman_t *am, hsk_addr_t *addr) {
  hsk_banned_t *entry = hsk_map_get(&am->banned, addr);

  if (!entry)
    return false;

  int64_t now = hsk_timedata_now(am->td);

  if (now > entry->time + HSK_BAN_TIME) {
    hsk_map_del(&am->banned, entry);
    free(entry);
    return false;
  }

  return true;
}

static hsk_addrentry_t *
hsk_addrman_search(hsk_addrman_t *am) {
  // randomly pick between fresh and used (track counts of each)
  int64_t now = hsk_timedata_now(am->td);

  double num = (double)(hsk_random() % (1 << 30));
  double factor = 1;

  for (;;) {
    int32_t i = hsk_random() % am->size;
    hsk_addrentry_t *entry = am->addrs[i];

    if (num < factor * hsk_addrentry_chance(entry, now) * (1 << 30))
      return entry;

    factor *= 1.2;
  }

  return NULL;
}

hsk_addrentry_t *
hsk_addrman_pick(hsk_addrman_t *am, hsk_map_t *map) {
  int64_t now = hsk_timedata_now(am->td);
  int32_t i;

  for (i = 0; i < 100; i++) {
    hsk_addrentry_t *entry = hsk_addrman_search(am);

    if (!entry)
      break;

    if (hsk_map_has(map, entry))
      continue;

    if (!hsk_addr_is_valid((hsk_addr_t *)entry))
      continue;

    if (!(entry->services & 1))
      continue;

    // if (hsk_addr_is_onion(addr))
    //   continue;

    if (i < 30 && now - entry->last_attempt < 600)
      continue;

    if (i < 50 && hsk_addr_get_port((hsk_addr_t *)entry) != HSK_PORT)
      continue;

    if (i < 95 && hsk_addrman_is_banned(am, (hsk_addr_t *)entry))
      continue;

    return entry;
  }

  return NULL;
}

bool
hsk_addrman_pick_addr(hsk_addrman_t *am, hsk_map_t *map, hsk_addr_t *addr) {
  hsk_addrentry_t *entry = hsk_addrman_pick(am, map);

  if (!entry)
    return false;

  hsk_addr_copy(addr, (hsk_addr_t *)entry);

  return true;
}

bool
hsk_addrman_pick_sa(hsk_addrman_t *am, hsk_map_t *map, struct sockaddr *addr) {
  hsk_addrentry_t *entry = hsk_addrman_pick(am, map);

  if (!entry)
    return false;

  hsk_addr_to_sa((hsk_addr_t *)entry, addr);

  return true;
}

static bool
hsk_addrman_is_stale(hsk_addrman_t *am, hsk_addrentry_t *entry) {
  int64_t now = hsk_timedata_now(am->td);

  if (entry->last_attempt && entry->last_attempt >= now - 60)
    return false;

  if (entry->time > now + 10 * 60)
    return true;

  if (entry->time == 0)
    return true;

  if (now - entry->time > HSK_HORIZON_DAYS * 24 * 60 * 60)
    return true;

  if (entry->last_success == 0 && entry->attempts >= HSK_RETRIES)
    return true;

  if (now - entry->last_success > HSK_MIN_FAIL_DAYS * 24 * 60 * 60) {
    if (entry->attempts >= HSK_MAX_FAILURES)
      return true;
  }

  return false;
}

static double
hsk_addrentry_chance(hsk_addrentry_t *entry, int64_t now) {
  double c = 1;

  if (now - entry->last_attempt < 60 * 10)
    c *= 0.01;

  c *= pow(0.66, min(entry->attempts, 8));

  return c;
}
