#ifndef _HSK_POOL_H
#define _HSK_POOL_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include "uv.h"

#include "hsk-addr.h"
#include "hsk-chain.h"
#include "hsk-header.h"
#include "hsk-map.h"
#include "hsk-timedata.h"
#include "hsk-addrmgr.h"

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

typedef void (*hsk_resolve_cb)(
  char *name,
  int32_t status,
  bool exists,
  uint8_t *data,
  size_t data_len,
  void *arg
);

typedef struct hsk_name_req_s {
  char name[256];
  uint8_t hash[32];
  uint8_t root[32];
  hsk_resolve_cb callback;
  void *arg;
  int64_t time;
  struct hsk_name_req_s *next;
} hsk_name_req_t;

typedef struct hsk_peer_s {
  void *pool;
  hsk_chain_t *chain;
  uv_loop_t *loop;
  uv_tcp_t socket;
  uint64_t id;
  char host[60];
  hsk_addr_t addr;
  uint16_t port;
  int32_t state;
  uint8_t read_buffer[HSK_BUFFER_SIZE];
  int32_t headers;
  int32_t proofs;
  int32_t height;
  hsk_map_t names;
  int64_t getheaders_time;
  int64_t version_time;
  int64_t last_ping;
  int64_t last_pong;
  int64_t min_ping;
  int64_t ping_timer;
  uint64_t challenge;
  int64_t conn_time;
  int64_t last_send;
  int64_t last_recv;
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
  hsk_timedata_t td;
  hsk_addrman_t am;
  uv_timer_t timer;
  uint64_t peer_id;
  hsk_map_t peers;
  hsk_peer_t *head;
  hsk_peer_t *tail;
  int32_t size;
  hsk_name_req_t *pending;
  int32_t pending_count;
  int64_t block_time;
  int64_t getheaders_time;
} hsk_pool_t;

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
