#ifndef _HSK_POOL_H
#define _HSK_POOL_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include "uv.h"

#include "hsk-chain.h"
#include "hsk-header.h"
#include "hsk-map.h"

/*
 * Defs
 */

#define HSK_BUFFER_SIZE 32768
#define HSK_POOL_SIZE 8
#define HSK_STATE_DISCONNECTED 0
#define HSK_STATE_CONNECTING 2
#define HSK_STATE_CONNECTED 3
#define HSK_STATE_READING 4
#define HSK_STATE_DISCONNECTING 5

/*
 * Types
 */

typedef struct hsk_peer_s {
  void *pool;
  hsk_chain_t *chain;
  uv_loop_t *loop;
  uv_tcp_t socket;
  uint64_t id;
  char host[60];
  int32_t family;
  uint8_t ip[16];
  uint16_t port;
  int32_t state;
  uint8_t read_buffer[HSK_BUFFER_SIZE];
  int32_t headers;
  int32_t proofs;
  int32_t height;
  hsk_map_t resolutions;
  int64_t getheaders_time;
  int64_t version_time;
  bool msg_hdr;
  uint8_t *msg;
  size_t msg_pos;
  size_t msg_len;
  char msg_cmd[12];
  uint8_t msg_sum[4];
  struct hsk_peer_s *next;
} hsk_peer_t;

typedef struct hsk_pool_s {
  uv_loop_t *loop;
  hsk_chain_t chain;
  uv_timer_t timer;
  uint64_t peer_id;
  hsk_peer_t *head;
  hsk_peer_t *tail;
  int32_t size;
  hsk_map_t resolutions;
} hsk_pool_t;

typedef void (*hsk_resolve_cb)(
  char *name,
  int32_t status,
  bool exists,
  uint8_t *data,
  size_t data_len,
  void *arg
);

/*
 * Pool
 */

int32_t
hsk_pool_init(hsk_pool_t *pool, uv_loop_t *loop);

void
hsk_pool_uninit(hsk_pool_t *pool);

hsk_pool_t *
hsk_pool_alloc(uv_loop_t *loop);

void
hsk_pool_free(hsk_pool_t *pool);

int32_t
hsk_pool_open(hsk_pool_t *pool);

int32_t
hsk_pool_close(hsk_pool_t *pool);

int32_t
hsk_pool_destroy(hsk_pool_t *pool);

int32_t
hsk_pool_resolve(
  hsk_pool_t *pool,
  char *name,
  hsk_resolve_cb callback,
  void *arg
);
#endif
