#ifndef _HSK_POOL_H
#define _HSK_POOL_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include "uv.h"

#include "addr.h"
#include "addrmgr.h"
#include "brontide.h"
#include "chain.h"
#include "ec.h"
#include "header.h"
#include "map.h"
#include "timedata.h"

/*
 * Defs
 */

#define HSK_BUFFER_SIZE 32768
#define HSK_POOL_SIZE 8
#define HSK_STATE_DISCONNECTED 0
#define HSK_STATE_CONNECTING 2
#define HSK_STATE_CONNECTED 3
#define HSK_STATE_READING 4
#define HSK_STATE_HANDSHAKE 5
#define HSK_STATE_DISCONNECTING 6
#define HSK_MAX_AGENT 255

/*
 * Types
 */

typedef void (*hsk_resolve_cb)(
  const char *name,
  int status,
  bool exists,
  const uint8_t *data,
  size_t data_len,
  const void *arg
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
  hsk_brontide_t *brontide;
  uint64_t id;
  char host[HSK_MAX_HOST];
  char agent[HSK_MAX_AGENT];
  hsk_addr_t addr;
  int state;
  uint8_t read_buffer[HSK_BUFFER_SIZE];
  int headers;
  int proofs;
  int64_t height;
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
  uint8_t msg_cmd;
  struct hsk_peer_s *next;
} hsk_peer_t;

typedef struct hsk_pool_s {
  uv_loop_t *loop;
  hsk_ec_t *ec;
  uint8_t key_[32];
  uint8_t *key;
  uint8_t pubkey[33];
  hsk_timedata_t td;
  hsk_chain_t chain;
  hsk_addrman_t am;
  uv_timer_t *timer;
  uint64_t peer_id;
  hsk_map_t peers;
  hsk_peer_t *head;
  hsk_peer_t *tail;
  int size;
  int max_size;
  hsk_name_req_t *pending;
  int pending_count;
  int64_t block_time;
  int64_t getheaders_time;
  char *user_agent;
} hsk_pool_t;

/*
 * Pool
 */

int
hsk_pool_init(hsk_pool_t *pool, const uv_loop_t *loop);

void
hsk_pool_uninit(hsk_pool_t *pool);

bool
hsk_pool_set_key(hsk_pool_t *pool, const uint8_t *key);

bool
hsk_pool_set_size(hsk_pool_t *pool, int max_size);

bool
hsk_pool_set_seeds(hsk_pool_t *pool, const char *seeds);

bool
hsk_pool_set_agent(hsk_pool_t *pool, const char *user_agent);

hsk_pool_t *
hsk_pool_alloc(const uv_loop_t *loop);

void
hsk_pool_free(hsk_pool_t *pool);

int
hsk_pool_open(hsk_pool_t *pool);

int
hsk_pool_close(hsk_pool_t *pool);

int
hsk_pool_destroy(hsk_pool_t *pool);

int
hsk_pool_resolve(
  hsk_pool_t *pool,
  const char *name,
  hsk_resolve_cb callback,
  const void *arg
);
#endif
