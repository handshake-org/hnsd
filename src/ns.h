#ifndef _HSK_NS_
#define _HSK_NS_

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include "uv.h"
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
  uv_udp_t socket;
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
