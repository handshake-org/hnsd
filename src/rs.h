#ifndef _HSK_RS_
#define _HSK_RS_

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include "unbound.h"
#include "uv.h"

/*
 * Types
 */

typedef struct {
  uv_loop_t *loop;
  struct ub_ctx *ub;
  uv_udp_t socket;
  uv_poll_t poll;
  uint8_t read_buffer[4096];
  bool bound;
  bool receiving;
  bool polling;
} hsk_rs_t;

/*
 * Recursive NS
 */

int32_t
hsk_rs_init(hsk_rs_t *ns, uv_loop_t *loop, struct sockaddr *addr);

void
hsk_rs_uninit(hsk_rs_t *ns);

int32_t
hsk_rs_open(hsk_rs_t *ns, struct sockaddr *addr);

int32_t
hsk_rs_close(hsk_rs_t *ns);

hsk_rs_t *
hsk_rs_alloc(uv_loop_t *loop, struct sockaddr *addr);

void
hsk_rs_free(hsk_rs_t *ns);

int32_t
hsk_rs_destroy(hsk_rs_t *ns);
#endif
