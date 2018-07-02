#ifndef _HSK_RS_
#define _HSK_RS_

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include <unbound.h>

#include "ec.h"
#include "uv.h"

/*
 * Types
 */

typedef struct {
  uv_loop_t *loop;
  struct ub_ctx *hns;
  struct ub_ctx *icann;
  uv_udp_t socket;
  uv_poll_t poll_hns;
  uv_poll_t poll_icann;
  hsk_ec_t *ec;
  char config_[256];
  char *config;
  struct sockaddr_storage stub_;
  struct sockaddr *stub;
  uint8_t key_[32];
  uint8_t *key;
  uint8_t pubkey[33];
  uint8_t read_buffer[4096];
  bool bound;
  bool receiving;
  bool polling;
} hsk_rs_t;

/*
 * Recursive NS
 */

int
hsk_rs_init(hsk_rs_t *ns, const uv_loop_t *loop, const struct sockaddr *stub);

void
hsk_rs_uninit(hsk_rs_t *ns);

bool
hsk_rs_set_config(hsk_rs_t *ns, const char *config);

bool
hsk_rs_set_key(hsk_rs_t *ns, const uint8_t *key);

int
hsk_rs_open(hsk_rs_t *ns, const struct sockaddr *addr);

int
hsk_rs_close(hsk_rs_t *ns);

hsk_rs_t *
hsk_rs_alloc(const uv_loop_t *loop, const struct sockaddr *stub);

void
hsk_rs_free(hsk_rs_t *ns);

int
hsk_rs_destroy(hsk_rs_t *ns);
#endif
