#ifndef _HSK_NS_
#define _HSK_NS_

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include "uv.h"

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
  hsk_addr_t *ip;
  hsk_addr_t _ip;
  uv_udp_t socket;
  hsk_ec_t *ec;
  uint8_t *key;
  uint8_t _key[32];
  uint8_t pubkey[33];
  uint8_t read_buffer[HSK_UDP_BUFFER];
  bool bound;
  bool receiving;
} hsk_ns_t;

/*
 * Root Nameserver
 */

int32_t
hsk_ns_init(hsk_ns_t *ns, uv_loop_t *loop, hsk_pool_t *pool);

void
hsk_ns_uninit(hsk_ns_t *ns);

void
hsk_ns_set_ip(hsk_ns_t *ns, struct sockaddr *addr);

bool
hsk_ns_set_key(hsk_ns_t *ns, uint8_t *key);

int32_t
hsk_ns_open(hsk_ns_t *ns, struct sockaddr *addr);

int32_t
hsk_ns_close(hsk_ns_t *ns);

hsk_ns_t *
hsk_ns_alloc(uv_loop_t *loop, hsk_pool_t *pool);

void
hsk_ns_free(hsk_ns_t *ns);

int32_t
hsk_ns_destroy(hsk_ns_t *ns);
#endif
