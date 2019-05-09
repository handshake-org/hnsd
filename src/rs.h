#ifndef _HSK_RS_
#define _HSK_RS_

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include <unbound.h>

#include "ec.h"
#include "rs_worker.h"
#include "uv.h"

/*
 * Types
 */

typedef struct {
  uv_loop_t *loop;
  struct ub_ctx *ub;
  uv_udp_t socket;
  hsk_rs_worker_t *rs_worker;
  hsk_ec_t *ec;
  char *config;
  struct sockaddr_storage stub_;
  struct sockaddr *stub;
  uint8_t key_[32];
  uint8_t *key;
  uint8_t pubkey[33];
  uint8_t read_buffer[4096];
  bool bound;
  bool receiving;
  void *stop_data;
  void (*stop_callback)(void *);
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

// Close the recursive name server.  This may complete asynchronously;
// stop_callback is called when the name server can be destroyed.
int
hsk_rs_close(hsk_rs_t *ns, void *stop_data, void (*stop_callback)(void *));

hsk_rs_t *
hsk_rs_alloc(const uv_loop_t *loop, const struct sockaddr *stub);

void
hsk_rs_free(hsk_rs_t *ns);
#endif
