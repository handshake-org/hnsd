#ifndef _HSK_NS_
#define _HSK_NS_

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include "uv.h"

#include "cache.h"
#include "ec.h"
#include "pool.h"

/*
 * Defs
 */

#define HSK_UDP_BUFFER 4096

/*
 * Types
 */

typedef struct {
  uv_loop_t *loop;
  hsk_pool_t *pool;
  hsk_addr_t ip_;
  hsk_addr_t *ip;
  uv_udp_t *socket;
  hsk_ec_t *ec;
  hsk_cache_t cache;
  uint8_t key_[32];
  uint8_t *key;
  uint8_t pubkey[33];
  uint8_t read_buffer[HSK_UDP_BUFFER];
  bool receiving;
  bool upstream;
} hsk_ns_t;

/*
 * Root Nameserver
 */

int
hsk_ns_init(
  hsk_ns_t *ns,
  const uv_loop_t *loop,
  const hsk_pool_t *pool,
  const bool upstream
);

void
hsk_ns_uninit(hsk_ns_t *ns);

bool
hsk_ns_set_ip(hsk_ns_t *ns, const struct sockaddr *addr);

bool
hsk_ns_set_key(hsk_ns_t *ns, const uint8_t *key);

int
hsk_ns_open(hsk_ns_t *ns, const struct sockaddr *addr);

int
hsk_ns_close(hsk_ns_t *ns);

hsk_ns_t *
hsk_ns_alloc(
  const uv_loop_t *loop,
  const hsk_pool_t *pool,
  const bool upstream
);

void
hsk_ns_free(hsk_ns_t *ns);

int
hsk_ns_destroy(hsk_ns_t *ns);
#endif
