#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "uv.h"

#include "hsk-chain.h"
#include "hsk-hash.h"
#include "hsk-header.h"
#include "hsk-resource.h"
#include "hsk-proof.h"
#include "hsk-error.h"
#include "hsk-constants.h"
#include "hsk-map.h"
#include "hsk-msg.h"
#include "utils.h"
#include "bn.h"
#include "pool.h"
#include "bio.h"

/*
 * Types
 */

typedef struct hsk_write_data_s {
  hsk_peer_t *peer;
  void *data;
  bool should_free;
} hsk_write_data_t;

/*
 * Templates
 */

static int32_t
hsk_pool_refill(hsk_pool_t *);

static hsk_peer_t *
hsk_peer_alloc(hsk_pool_t *);

static void
hsk_peer_free(hsk_peer_t *);

static void
hsk_peer_push(hsk_peer_t *);

static int32_t
hsk_peer_open(hsk_peer_t *, struct sockaddr *);

static int32_t
hsk_peer_close(hsk_peer_t *);

static void
hsk_peer_log(hsk_peer_t *, const char *, ...);

static void
hsk_peer_remove(hsk_peer_t *);

static int32_t
hsk_peer_destroy(hsk_peer_t *);

static int32_t
hsk_peer_parse(hsk_peer_t *, uint8_t *, size_t);

static int32_t
hsk_peer_send_ping(hsk_peer_t *, uint64_t);

static int32_t
hsk_peer_send_getheaders(hsk_peer_t *, uint8_t *);

static int32_t
hsk_peer_send_getproof(hsk_peer_t *, uint8_t *, uint8_t *);

static void
on_connect(uv_connect_t *, int);

static void
alloc_buffer(uv_handle_t *, size_t, uv_buf_t *);

static void
after_write(uv_write_t *, int);

static void
after_read(uv_stream_t *, long int, const uv_buf_t *);

static void
after_close(uv_handle_t *);

static void
after_timer(uv_timer_t *);

void
hsk_chain_get_locator(hsk_chain_t *chain, hsk_getheaders_msg_t *msg);

/*
 * Pool
 */

int32_t
hsk_pool_init(hsk_pool_t *pool, uv_loop_t *loop) {
  if (!pool || !loop)
    return HSK_EBADARGS;

  pool->loop = loop;
  hsk_chain_init(&pool->chain);
  pool->peer_id = 0;
  pool->head = NULL;
  pool->tail = NULL;
  pool->size = 0;
  pool->pending = NULL;
  pool->pending_count = 0;
  pool->block_time = 0;
  pool->getheaders_time = 0;

  return HSK_SUCCESS;
}

void
hsk_pool_uninit(hsk_pool_t *pool) {
  if (!pool)
    return;

  hsk_peer_t *peer, *next;
  for (peer = pool->head; peer; peer = next) {
    next = peer->next;
    hsk_peer_destroy(peer);
  }

  hsk_name_req_t *req, *n;
  for (req = pool->pending; req; req = n) {
    n = req->next;
    free(req);
  }

  pool->pending = NULL;
  pool->pending_count = 0;

  hsk_chain_uninit(&pool->chain);
}

hsk_pool_t *
hsk_pool_alloc(uv_loop_t *loop) {
  hsk_pool_t *pool = malloc(sizeof(hsk_pool_t));

  if (!pool)
    return NULL;

  if (hsk_pool_init(pool, loop) != HSK_SUCCESS) {
    hsk_pool_free(pool);
    return NULL;
  }

  return pool;
}

void
hsk_pool_free(hsk_pool_t *pool) {
  if (!pool)
    return;

  hsk_pool_uninit(pool);
  free(pool);
}

int32_t
hsk_pool_open(hsk_pool_t *pool) {
  if (!pool)
    return HSK_EBADARGS;

  pool->timer.data = (void *)pool;

  if (uv_timer_init(pool->loop, &pool->timer) != 0)
    return HSK_EFAILURE;

  if (uv_timer_start(&pool->timer, after_timer, 3000, 3000) != 0)
    return HSK_EFAILURE;

  hsk_pool_refill(pool);

  return HSK_SUCCESS;
}

int32_t
hsk_pool_close(hsk_pool_t *pool) {
  if (!pool)
    return HSK_EBADARGS;

  if (uv_timer_stop(&pool->timer) != 0)
    return HSK_EFAILURE;

  hsk_pool_uninit(pool);

  return HSK_SUCCESS;
}

int32_t
hsk_pool_destroy(hsk_pool_t *pool) {
  if (!pool)
    return HSK_EBADARGS;

  hsk_pool_free(pool);

  return HSK_SUCCESS;
}

static void
hsk_pool_log(hsk_pool_t *pool, const char *fmt, ...) {
  printf("pool: ");

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

static void
hsk_pool_getaddr(hsk_pool_t *pool, struct sockaddr *addr) {
  assert(hsk_string2inet("127.0.0.1", addr, HSK_PORT));
}

static int32_t
hsk_pool_refill(hsk_pool_t *pool) {
  while (pool->size < HSK_POOL_SIZE) {
    hsk_peer_t *peer = hsk_peer_alloc(pool);
    hsk_peer_push(peer);

    struct sockaddr_storage addr;
    hsk_pool_getaddr(pool, (struct sockaddr *)&addr);

    int32_t rc = hsk_peer_open(peer, (struct sockaddr *)&addr);

    if (rc != HSK_SUCCESS) {
      hsk_peer_destroy(peer);
      return rc;
    }
  }

  return HSK_SUCCESS;
}

static hsk_peer_t *
hsk_pool_pick_prover(hsk_pool_t *pool, uint8_t *name_hash) {
  hsk_peer_t *first_best = pool->head;
  hsk_peer_t *second_best = NULL;
  hsk_peer_t *deterministic = NULL;
  hsk_peer_t *random = NULL;

  int32_t total = 0;

  hsk_peer_t *peer;
  for (peer = pool->head; peer; peer = peer->next) {
    if (peer->state != HSK_STATE_READING)
      continue;

    if (peer->proofs > first_best->proofs
        && peer->names.size <= first_best->names.size) {
      second_best = first_best;
      first_best = peer;
    }

    total += 1;
  }

  int32_t i = name_hash[0] % total;
  int32_t r = hsk_random() % total;

  for (peer = pool->head; peer; peer = peer->next) {
    if (peer->state != HSK_STATE_READING)
      continue;

    if (i == 0)
      deterministic = peer;

    if (r == 0)
      random = peer;

    i -= 1;
    r -= 1;
  }

  if (random && (hsk_random() % 5) == 0)
    return random;

  if (second_best && (hsk_random() % 10) == 0)
    return second_best;

  if (first_best && (hsk_random() % 10) == 0)
    return first_best;

  return deterministic;
}

int32_t
hsk_pool_resolve(
  hsk_pool_t *pool,
  char *name,
  hsk_resolve_cb callback,
  void *arg
) {
  if (!hsk_chain_synced(&pool->chain))
    return HSK_ETIMEOUT;

  uint8_t *root = pool->chain.tip->trie_root;
  hsk_name_req_t *req = malloc(sizeof(hsk_name_req_t));

  if (!req)
    return HSK_ENOMEM;

  strcpy(req->name, name);

  hsk_hash_blake2b(name, strlen(name), req->hash);

  memcpy(req->root, root, 32);

  req->callback = callback;
  req->arg = arg;
  req->time = hsk_now();
  req->next = NULL;

  hsk_peer_t *peer = hsk_pool_pick_prover(pool, req->hash);

  // Insert into a "pending" list.
  if (!peer) {
    req->next = pool->pending;
    pool->pending = req;
    pool->pending_count += 1;
    return HSK_SUCCESS;
  }

  hsk_name_req_t *head = hsk_map_get(&peer->names, req->hash);

  if (!hsk_map_set(&peer->names, req->hash, (void *)req)) {
    free(req);
    return HSK_ENOMEM;
  }

  if (head) {
    req->next = head;
    req->time = head->time;
    return HSK_SUCCESS;
  }

  return hsk_peer_send_getproof(peer, req->hash, root);
}

static void
hsk_pool_resend(hsk_pool_t *pool) {
  if (!hsk_chain_synced(&pool->chain))
    return;

  uint8_t *root = pool->chain.tip->trie_root;
  hsk_name_req_t *req = pool->pending;

  if (!req)
    return;

  hsk_peer_t *peer = hsk_pool_pick_prover(pool, req->hash);

  if (!peer)
    return;

  hsk_name_req_t *next;

  pool->pending = NULL;
  pool->pending_count = 0;

  int64_t now = hsk_now();

  for (; req; req = next) {
    next = req->next;

    hsk_peer_t *peer = hsk_pool_pick_prover(pool, req->hash);
    assert(peer);

    req->next = NULL;
    req->time = now;

    hsk_name_req_t *head = hsk_map_get(&peer->names, req->hash);

    if (!hsk_map_set(&peer->names, req->hash, (void *)req)) {
      free(req);
      continue;
    }

    if (head) {
      req->next = head;
      continue;
    }

    hsk_peer_send_getproof(peer, req->hash, root);
  }
}

static void
hsk_pool_send_getheaders(hsk_pool_t *pool) {
  hsk_peer_t *peer;

  for (peer = pool->head; peer; peer = peer->next) {
    if (peer->state != HSK_STATE_READING)
      continue;

    hsk_peer_send_getheaders(peer, NULL);
  }

  pool->getheaders_time = hsk_now();
}

static void
hsk_pool_merge_reqs(hsk_pool_t *pool, hsk_map_t *map) {
  hsk_map_iter_t i;

  for (i = hsk_map_begin(map); i != hsk_map_end(map); i++) {
    if (!hsk_map_exists(map, i))
      continue;

    hsk_name_req_t *req = (hsk_name_req_t *)hsk_map_value(map, i);
    assert(req);

    hsk_name_req_t *tail;
    int32_t count = 0;

    for (tail = req; tail; tail = tail->next) {
      count += 1;
      if (!tail->next)
        break;
    }

    if (tail) {
      tail->next = pool->pending;
      pool->pending = req;
      pool->pending_count += count;
    }
  }

  hsk_map_reset(map);

  if (pool->pending_count > 100) {
    hsk_name_req_t *req, *next;

    for (req = pool->pending; req; req = next) {
      next = req->next;

      req->callback(
        req->name,
        HSK_ETIMEOUT,
        false,
        NULL,
        0,
        req->arg
      );

      free(req);
    }

    pool->pending_count = 0;
  }
}

static void
hsk_peer_timeout_reqs(hsk_peer_t *peer) {
  hsk_map_t *map = &peer->names;
  hsk_map_iter_t i;

  for (i = hsk_map_begin(map); i != hsk_map_end(map); i++) {
    if (!hsk_map_exists(map, i))
      continue;

    hsk_name_req_t *req = (hsk_name_req_t *)hsk_map_value(map, i);
    hsk_name_req_t *next;

    assert(req);

    hsk_map_delete(map, i);

    for (; req; req = next) {
      next = req->next;

      req->callback(
        req->name,
        HSK_ETIMEOUT,
        false,
        NULL,
        0,
        req->arg
      );

      free(req);
    }
  }

  hsk_map_reset(map);
}

static bool
hsk_peer_is_overdue(hsk_peer_t *peer) {
  int64_t now = hsk_now();

  hsk_map_t *map = &peer->names;
  hsk_map_iter_t i;

  for (i = hsk_map_begin(map); i != hsk_map_end(map); i++) {
    if (!hsk_map_exists(map, i))
      continue;

    hsk_name_req_t *req = (hsk_name_req_t *)hsk_map_value(map, i);
    assert(req);

    if (now > req->time + 5)
      return true;
  }

  return false;
}

static void
hsk_pool_timer(hsk_pool_t *pool) {
  hsk_peer_t *peer, *next;
  int64_t now = hsk_now();

  for (peer = pool->head; peer; peer = next) {
    next = peer->next;

    if (peer->state != HSK_STATE_READING)
      continue;

    if (now > peer->conn_time + 60) {
      if (peer->last_send == 0 || peer->last_recv == 0) {
        hsk_peer_log(peer, "peer is stalling (no message)\n");
        hsk_peer_destroy(peer);
        continue;
      }

      if (now > peer->last_send + 20 * 60) {
        hsk_peer_log(peer, "peer is stalling (no send)\n");
        hsk_peer_destroy(peer);
        continue;
      }

      if (now > peer->last_recv + 20 * 60) {
        hsk_peer_log(peer, "peer is stalling (no recv)\n");
        hsk_peer_destroy(peer);
        continue;
      }

      if (peer->challenge && now > peer->last_ping + 20 * 60) {
        hsk_peer_log(peer, "peer is stalling (ping)\n");
        hsk_peer_destroy(peer);
        continue;
      }
    }

    if (now > peer->ping_timer + 30) {
      peer->ping_timer = now;
      if (peer->challenge) {
        hsk_peer_log(peer, "peer has not responded to ping\n");
      } else {
        hsk_peer_log(peer, "pinging...\n");
        peer->challenge = hsk_nonce();
        peer->last_ping = now;
        hsk_peer_send_ping(peer, peer->challenge);
      }
    }

    if (!hsk_chain_synced(&pool->chain)) {
      if (peer->getheaders_time && now > peer->getheaders_time + 30) {
        hsk_peer_log(peer, "peer is stalling (headers)\n");
        hsk_peer_destroy(peer);
        continue;
      }
    }

    if (peer->version_time && now > peer->version_time + 10) {
      hsk_peer_log(peer, "peer is stalling (verack)\n");
      hsk_peer_destroy(peer);
      continue;
    }

    if (hsk_peer_is_overdue(peer)) {
      hsk_peer_log(peer, "peer is stalling (overdue)\n");
      hsk_peer_destroy(peer);
      continue;
    }
  }

  if (pool->block_time && now > pool->block_time + 10 * 60) {
    if (!pool->getheaders_time || now > pool->getheaders_time + 5 * 60) {
      hsk_pool_log(pool, "resending getheaders to pool\n");
      hsk_pool_send_getheaders(pool);
    }
  }

  hsk_pool_refill(pool);
}

/*
 * Peer
 */

static int32_t
hsk_peer_init(hsk_peer_t *peer, hsk_pool_t *pool) {
  if (!peer || !pool)
    return HSK_EBADARGS;

  assert(pool && pool->loop);

  peer->pool = (void *)pool;
  peer->chain = &pool->chain;
  peer->loop = pool->loop;
  peer->id = pool->peer_id++;
  memset(peer->host, 0, sizeof(peer->host));
  peer->family = AF_INET;
  memset(peer->ip, 0, 16);
  peer->port = 0;
  peer->state = HSK_STATE_DISCONNECTED;
  memset(peer->read_buffer, 0, HSK_BUFFER_SIZE);
  peer->headers = 0;
  peer->proofs = 0;
  peer->height = 0;
  hsk_map_init_hash_map(&peer->names, free);
  peer->getheaders_time = 0;
  peer->version_time = 0;
  peer->last_ping = 0;
  peer->last_pong = 0;
  peer->min_ping = 0;
  peer->ping_timer = 0;
  peer->challenge = 0;
  peer->conn_time = 0;
  peer->last_send = 0;
  peer->last_recv = 0;
  peer->msg_hdr = false;
  peer->msg = (uint8_t *)malloc(24);
  peer->msg_pos = 0;
  peer->msg_len = 24;
  memset(peer->msg_cmd, 0, sizeof peer->msg_cmd);
  memset(peer->msg_sum, 0, sizeof peer->msg_sum);
  peer->next = NULL;

  if (!peer->msg)
    goto fail;

  return HSK_SUCCESS;

fail:
  if (peer->msg) {
    free(peer->msg);
    peer->msg = NULL;
  }

  return HSK_ENOMEM;
}

static void
hsk_peer_uninit(hsk_peer_t *peer) {
  if (!peer)
    return;

  hsk_map_uninit(&peer->names);

  if (peer->msg) {
    free(peer->msg);
    peer->msg = NULL;
  }
}

static hsk_peer_t *
hsk_peer_alloc(hsk_pool_t *pool) {
  hsk_peer_t *peer = malloc(sizeof(hsk_peer_t));

  if (!peer)
    return NULL;

  if (hsk_peer_init(peer, pool) != HSK_SUCCESS) {
    hsk_peer_free(peer);
    return NULL;
  }

  return peer;
}

static void
hsk_peer_free(hsk_peer_t *peer) {
  if (!peer)
    return;

  hsk_peer_uninit(peer);
  free(peer);
}

static int32_t
hsk_peer_open(hsk_peer_t *peer, struct sockaddr *addr) {
  assert(peer->pool && peer->loop && peer->state == HSK_STATE_DISCONNECTED);

  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;
  uv_loop_t *loop = pool->loop;

  if (uv_tcp_init(loop, &peer->socket) != 0)
    return HSK_EFAILURE;

  peer->socket.data = (void *)peer;

  if (!hsk_get_inet(addr, &peer->family, peer->ip, &peer->port))
    return HSK_EBADARGS;

  if (!hsk_inet2string(addr, peer->host, sizeof(peer->host) - 1, HSK_PORT))
    return HSK_EBADARGS;

  uv_connect_t *conn = malloc(sizeof(uv_connect_t));

  if (!conn)
    return HSK_ENOMEM;

  if (uv_tcp_connect(conn, &peer->socket, addr, on_connect) != 0) {
    free(conn);
    return HSK_EFAILURE;
  }

  peer->state = HSK_STATE_CONNECTING;

  return HSK_SUCCESS;
}

static int32_t
hsk_peer_close(hsk_peer_t *peer) {
  switch (peer->state) {
    case HSK_STATE_DISCONNECTING:
      return HSK_SUCCESS;
    case HSK_STATE_READING:
      assert(uv_read_stop((uv_stream_t *)&peer->socket) == 0);
    case HSK_STATE_CONNECTED:
    case HSK_STATE_CONNECTING:
      uv_close((uv_handle_t *)&peer->socket, after_close);
      hsk_peer_log(peer, "closing peer\n");
      break;
    case HSK_STATE_DISCONNECTED:
      assert(false);
      break;
    default:
      assert(false);
      break;
  }

  peer->state = HSK_STATE_DISCONNECTING;
  // hsk_pool_merge_reqs(peer->pool, &peer->names);
  hsk_peer_timeout_reqs(peer);
  hsk_peer_remove(peer);

  return HSK_SUCCESS;
}

static int32_t
hsk_peer_destroy(hsk_peer_t *peer) {
  return hsk_peer_close(peer);
}

static void
hsk_peer_log(hsk_peer_t *peer, const char *fmt, ...) {
  printf("peer %d (%s): ", peer->id, peer->host);

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

static void
hsk_peer_push(hsk_peer_t *peer) {
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  if (!peer)
    return;

  peer->next = NULL;

  if (!pool->head)
    pool->head = peer;

  if (pool->tail)
    pool->tail->next = peer;

  pool->tail = peer;
  pool->size += 1;
}

static void
hsk_peer_remove(hsk_peer_t *peer) {
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  if (!peer)
    return;

  if (!pool->head)
    return;

  if (pool->head == peer) {
    if (pool->tail == peer)
      pool->tail = NULL;
    pool->head = peer->next;
    peer->next = NULL;
    pool->size -= 1;
    return;
  }

  hsk_peer_t *prev;

  // O(n), but who cares.
  for (prev = pool->head; prev; prev = prev->next) {
    if (prev->next == peer)
      break;
  }

  if (!prev)
    return;

  if (pool->tail == peer)
    pool->tail = prev;

  prev->next = peer->next;

  pool->size -= 1;
}

static int32_t
hsk_peer_write(
  hsk_peer_t *peer,
  uint8_t *data,
  size_t data_len,
  bool should_free
) {
  if (peer->state == HSK_STATE_DISCONNECTING)
    return HSK_SUCCESS;

  int32_t rc = HSK_SUCCESS;
  hsk_write_data_t *wd = NULL;
  uv_write_t *req = NULL;

  wd = (hsk_write_data_t *)malloc(sizeof(hsk_write_data_t));

  if (!wd) {
    rc = HSK_ENOMEM;
    goto fail;
  }

  req = (uv_write_t *)malloc(sizeof(uv_write_t));

  if (!req) {
    rc = HSK_ENOMEM;
    goto fail;
  }

  wd->peer = peer;
  wd->data = (void *)data;
  wd->should_free = should_free;

  req->data = (void *)wd;

  uv_stream_t *stream = (uv_stream_t *)&peer->socket;

  uv_buf_t bufs[] = {
    { .base = data, .len = data_len }
  };

  int status = uv_write(req, stream, bufs, 1, after_write);

  if (status != 0) {
    hsk_pool_t *pool = (hsk_pool_t *)peer->pool;
    hsk_peer_log(peer, "failed writing: %s\n", uv_strerror(status));
    hsk_peer_destroy(peer);
    rc = HSK_EFAILURE;
    goto fail;
  }

  peer->last_send = hsk_now();

  return rc;

fail:
  if (wd)
    free(wd);

  if (req)
    free(req);

  if (should_free)
    free(data);

  return rc;
}

static int32_t
hsk_peer_send(hsk_peer_t *peer, hsk_msg_t *msg) {
  int32_t msg_size = hsk_msg_size(msg);
  assert(msg_size != -1);

  size_t size = 24 + msg_size;
  uint8_t *data = malloc(size);

  if (!data)
    return HSK_ENOMEM;

  uint8_t *buf = data;

  // Magic Number
  write_u32(&buf, HSK_MAGIC);

  // Command
  const char *cmd = hsk_msg_str(msg->cmd);
  size_t len = strlen(cmd);
  write_bytes(&buf, (uint8_t *)cmd, len);

  // Padding
  int32_t i;
  for (i = len; i < 12; i++)
    write_u8(&buf, 0);

  // Msg Size
  write_u32(&buf, msg_size);

  // Checksum
  write_u32(&buf, 0);

  // Msg
  hsk_msg_write(msg, &buf);

  // Compute Checksum
  uint8_t hash[32];
  hsk_hash_hash256(data + 24, size - 24, hash);
  memcpy(data + 20, hash, 4);

  return hsk_peer_write(peer, data, size, true);
}

static int32_t
hsk_peer_send_version(hsk_peer_t *peer, hsk_version_msg_t *theirs) {
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  hsk_version_msg_t msg = { .cmd = HSK_MSG_VERSION };
  hsk_msg_init((hsk_msg_t *)&msg);

  msg.version = HSK_PROTO_VERSION;
  msg.services = HSK_SERVICES;
  msg.time = hsk_now();

  if (theirs) {
    msg.remote.time = theirs->time;
    msg.remote.services = theirs->services;
  }

  msg.remote.type = 0;
  memcpy(msg.remote.addr, peer->ip, 16);
  msg.remote.port = peer->port;
  msg.nonce = hsk_nonce();
  strcpy(msg.agent, HSK_USER_AGENT);
  msg.height = pool->chain.height;

  peer->version_time = hsk_now();

  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int32_t
hsk_peer_send_verack(hsk_peer_t *peer) {
  hsk_version_msg_t msg = { .cmd = HSK_MSG_VERACK };
  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int32_t
hsk_peer_send_ping(hsk_peer_t *peer, uint64_t nonce) {
  hsk_ping_msg_t msg = {
    .cmd = HSK_MSG_PING,
    .nonce = nonce
  };
  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int32_t
hsk_peer_send_pong(hsk_peer_t *peer, uint64_t nonce) {
  hsk_pong_msg_t msg = {
    .cmd = HSK_MSG_PONG,
    .nonce = nonce
  };
  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int32_t
hsk_peer_send_sendheaders(hsk_peer_t *peer) {
  hsk_version_msg_t msg = { .cmd = HSK_MSG_SENDHEADERS };
  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int32_t
hsk_peer_send_getheaders(hsk_peer_t *peer, uint8_t *stop) {
  hsk_getheaders_msg_t msg = { .cmd = HSK_MSG_GETHEADERS };

  hsk_msg_init((hsk_msg_t *)&msg);

  hsk_chain_get_locator(peer->chain, &msg);

  if (stop)
    memcpy(msg.stop, stop, 32);

  peer->getheaders_time = hsk_now();

  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int32_t
hsk_peer_send_getproof(hsk_peer_t *peer, uint8_t *name_hash, uint8_t *root) {
  hsk_getproof_msg_t msg = { .cmd = HSK_MSG_GETPROOF };
  hsk_msg_init((hsk_msg_t *)&msg);

  memcpy(msg.name_hash, name_hash, 32);
  memcpy(msg.root, root, 32);

  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int32_t
hsk_peer_handle_version(hsk_peer_t *peer, hsk_version_msg_t *msg) {
  int32_t rc = hsk_peer_send_verack(peer);

  if (rc != HSK_SUCCESS)
    return rc;

  hsk_peer_log(peer, "received version: %s (%d)\n", msg->agent, msg->height);
  peer->height = msg->height;

  return hsk_peer_send_version(peer, msg);
}

static int32_t
hsk_peer_handle_verack(hsk_peer_t *peer, hsk_verack_msg_t *msg) {
  int32_t rc = hsk_peer_send_sendheaders(peer);

  peer->version_time = 0;

  if (rc != HSK_SUCCESS)
    return rc;

  return hsk_peer_send_getheaders(peer, NULL);
}

static int32_t
hsk_peer_handle_ping(hsk_peer_t *peer, hsk_ping_msg_t *msg) {
  return hsk_peer_send_pong(peer, msg->nonce);
}

static int32_t
hsk_peer_handle_pong(hsk_peer_t *peer, hsk_pong_msg_t *msg) {
  if (!peer->challenge) {
    hsk_peer_log(peer, "peer sent an unsolicited pong\n");
    return HSK_SUCCESS;
  }

  if (msg->nonce != peer->challenge) {
    if (msg->nonce == 0) {
      hsk_peer_log(peer, "peer sent a zero nonce\n");
      peer->challenge = 0;
      return HSK_SUCCESS;
    }
    hsk_peer_log(peer, "peer sent the wrong nonce\n");
    return HSK_SUCCESS;
  }

  hsk_peer_log(peer, "received pong\n");

  int64_t now = hsk_now();
  if (hsk_now() >= peer->last_ping) {
    int64_t min = now - peer->last_ping;
    peer->last_pong = now;
    if (!peer->min_ping)
      peer->min_ping = min;
    peer->min_ping = peer->min_ping < min ? peer->min_ping : min;
  } else {
    hsk_peer_log(peer, "timing mismatch\n");
  }

  peer->challenge = 0;

  return HSK_SUCCESS;
}

static int32_t
hsk_peer_handle_addr(hsk_peer_t *peer, hsk_addr_msg_t *msg) {
  hsk_peer_log(peer, "received %d addrs\n", msg->addr_count);
  // int32_t i;
  // for (i = 0; i < m->addr_count; i++)
  //   hsk_netaddr_t *addr = &m->addrs[i];
  return HSK_SUCCESS;
}

static int32_t
hsk_peer_handle_headers(hsk_peer_t *peer, hsk_headers_msg_t *msg) {
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  hsk_peer_log(peer, "received %d headers\n", msg->header_count);

  if (msg->header_count == 0)
    return HSK_SUCCESS;

  if (msg->header_count > 2000)
    return HSK_EFAILURE;

  uint8_t *last = NULL;
  hsk_header_t *hdr;

  for (hdr = msg->headers; hdr; hdr = hdr->next) {
    if (last && memcmp(hdr->prev_block, last, 32) != 0) {
      hsk_peer_log(peer, "invalid header chain\n");
      return HSK_EHASHMISMATCH;
    }

    last = hsk_header_cache(hdr);

    int32_t rc = hsk_header_verify_pow(hdr);

    if (rc != HSK_SUCCESS) {
      hsk_peer_log(peer, "invalid header pow\n");
      return rc;
    }
  }

  for (hdr = msg->headers; hdr; hdr = hdr->next) {
    int32_t rc = hsk_chain_add(peer->chain, hdr);

    if (rc != HSK_SUCCESS) {
      hsk_peer_log(peer, "failed adding block: %d\n", rc);
      return rc;
    }

    peer->headers += 1;
  }

  pool->block_time = hsk_now();
  peer->getheaders_time = 0;

  if (msg->header_count == 2000) {
    hsk_peer_log(peer, "requesting more headers\n");
    return hsk_peer_send_getheaders(peer, NULL);
  }

  return HSK_SUCCESS;
}

static int32_t
hsk_peer_handle_proof(hsk_peer_t *peer, hsk_proof_msg_t *msg) {
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  hsk_peer_log(peer, "received proof: %s\n", hsk_hex_encode32(msg->name_hash));

  hsk_name_req_t *reqs = hsk_map_get(&peer->names, msg->name_hash);

  if (!reqs) {
    hsk_peer_log(peer,
      "received unsolicited proof: %s\n",
      hsk_hex_encode32(msg->name_hash));
    return HSK_EBADARGS;
  }

  hsk_peer_log(peer, "received proof for: %s\n", reqs->name);

  if (memcmp(msg->root, reqs->root, 32) != 0) {
    hsk_peer_log(peer, "proof hash mismatch (why?)\n");
    return HSK_EHASHMISMATCH;
  }

  bool exists = false;
  int32_t rc = hsk_proof_verify(
    msg->root,
    msg->name_hash,
    msg->nodes,
    msg->data,
    msg->data_len,
    &exists
  );

  if (rc != HSK_SUCCESS) {
    hsk_peer_log(peer, "invalid proof: %d\n", rc);
    return rc;
  }

  hsk_map_del(&peer->names, msg->name_hash);

  hsk_name_req_t *req, *next;

  for (req = reqs; req; req = next) {
    next = req->next;

    req->callback(
      req->name,
      HSK_SUCCESS,
      exists,
      msg->data,
      msg->data_len,
      req->arg
    );

    free(req);
  }

  peer->proofs += 1;

  return HSK_SUCCESS;
}

static int32_t
hsk_peer_handle_msg(hsk_peer_t *peer, hsk_msg_t *msg) {
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  hsk_peer_log(peer, "handling msg: %s\n", hsk_msg_str(msg->cmd));

  switch (msg->cmd) {
    case HSK_MSG_VERSION: {
      return hsk_peer_handle_version(peer, (hsk_version_msg_t *)msg);
    }
    case HSK_MSG_VERACK: {
      return hsk_peer_handle_verack(peer, (hsk_verack_msg_t *)msg);
    }
    case HSK_MSG_PING: {
      return hsk_peer_handle_ping(peer, (hsk_ping_msg_t *)msg);
    }
    case HSK_MSG_PONG: {
      return hsk_peer_handle_pong(peer, (hsk_pong_msg_t *)msg);
    }
    case HSK_MSG_GETADDR: {
      hsk_peer_log(peer, "cannot handle getaddr\n");
      return HSK_SUCCESS;
    }
    case HSK_MSG_ADDR: {
      return hsk_peer_handle_addr(peer, (hsk_addr_msg_t *)msg);
    }
    case HSK_MSG_GETHEADERS: {
      hsk_peer_log(peer, "cannot handle getheaders\n");
      return HSK_SUCCESS;
    }
    case HSK_MSG_HEADERS: {
      return hsk_peer_handle_headers(peer, (hsk_headers_msg_t *)msg);
    }
    case HSK_MSG_SENDHEADERS: {
      hsk_peer_log(peer, "cannot handle sendheaders\n");
      return HSK_SUCCESS;
    }
    case HSK_MSG_GETPROOF: {
      hsk_peer_log(peer, "cannot handle getproof\n");
      return HSK_SUCCESS;
    }
    case HSK_MSG_PROOF: {
      return hsk_peer_handle_proof(peer, (hsk_proof_msg_t *)msg);
    }
    case HSK_MSG_UNKNOWN:
    default: {
      return HSK_SUCCESS;
    }
  }
}

static void
hsk_peer_on_read(hsk_peer_t *peer, uint8_t *data, size_t data_len) {
  if (peer->state != HSK_STATE_READING)
    return;

  peer->last_recv = hsk_now();

  while (peer->msg_pos + data_len >= peer->msg_len) {
    size_t need = peer->msg_len - peer->msg_pos;
    memcpy(peer->msg + peer->msg_pos, data, need);
    data += need;
    data_len -= need;
    hsk_peer_parse(peer, peer->msg, peer->msg_len);
  }

  memcpy(peer->msg + peer->msg_pos, data, data_len);
  peer->msg_pos += data_len;
}

static int32_t
hsk_peer_parse_hdr(hsk_peer_t *peer, uint8_t *msg, size_t msg_len) {
  uint32_t magic;

  if (!read_u32(&msg, &msg_len, &magic)) {
    hsk_peer_log(peer, "invalid header\n");
    return HSK_EENCODING;
  }

  if (magic != HSK_MAGIC) {
    hsk_peer_log(peer, "invalid magic: %x\n", magic);
    return HSK_EENCODING;
  }

  int32_t i = 0;
  for (; msg[i] != 0 && i < 12; i++);

  if (i == 12) {
    hsk_peer_log(peer, "invalid command\n");
    return HSK_EENCODING;
  }

  memcpy(peer->msg_cmd, msg, i + 1);

  msg += 12;
  msg_len -= 12;

  uint32_t size;

  if (!read_u32(&msg, &msg_len, &size)) {
    hsk_peer_log(peer, "invalid header: %s\n", peer->msg_cmd);
    return HSK_EENCODING;
  }

  if (size > HSK_MAX_MESSAGE) {
    hsk_peer_log(peer, "invalid msg size: %s - %d\n", peer->msg_cmd, size);
    return HSK_EENCODING;
  }

  if (!read_bytes(&msg, &msg_len, peer->msg_sum, 4)) {
    hsk_peer_log(peer, "invalid header: %s\n", peer->msg_cmd);
    return HSK_EENCODING;
  }

  msg = realloc(peer->msg, size);

  if (!msg && size != 0)
    return HSK_ENOMEM;

  peer->msg_hdr = true;
  peer->msg = msg;
  peer->msg_pos = 0;
  peer->msg_len = size;

  hsk_peer_log(peer, "received header: %s\n", peer->msg_cmd);
  hsk_peer_log(peer, "  msg size: %d\n", peer->msg_len);

  return HSK_SUCCESS;
}

static int32_t
hsk_peer_parse(hsk_peer_t *peer, uint8_t *msg, size_t msg_len) {
  if (!peer->msg_hdr)
    return hsk_peer_parse_hdr(peer, msg, msg_len);

  int32_t rc = HSK_SUCCESS;
  uint8_t hash[32];
  hsk_hash_hash256(msg, msg_len, hash);

  if (memcmp(hash, peer->msg_sum, 4) != 0) {
    hsk_peer_log(peer, "invalid checksum: %s\n", peer->msg_cmd);
    rc = HSK_EENCODING;
    goto done;
  }

  uint8_t cmd = hsk_msg_cmd(peer->msg_cmd);

  if (cmd == HSK_MSG_UNKNOWN) {
    hsk_peer_log(peer, "unknown command: %s\n", peer->msg_cmd);
    goto done;
  }

  hsk_msg_t *m = hsk_msg_alloc(cmd);

  if (!m) {
    rc = HSK_ENOMEM;
    goto done;
  }

  if (!hsk_msg_decode(msg, msg_len, m)) {
    hsk_peer_log(peer, "error parsing msg: %s\n", peer->msg_cmd);
    free(m);
    rc = HSK_EENCODING;
    goto done;
  }

  rc = hsk_peer_handle_msg(peer, m);
  hsk_msg_free(m);

done:
  msg = realloc(peer->msg, 24);

  if (!msg)
    return HSK_ENOMEM;

  peer->msg_hdr = false;
  peer->msg = msg;
  peer->msg_pos = 0;
  peer->msg_len = 24;
  memset(peer->msg_cmd, 0, sizeof peer->msg_cmd);
  memset(peer->msg_sum, 0, sizeof peer->msg_sum);

  return rc;
}

/*
 * UV behavior
 */

static void
on_connect(uv_connect_t *conn, int32_t status) {
  uv_tcp_t *socket = (uv_tcp_t *)conn->handle;
  free(conn);

  hsk_peer_t *peer = (hsk_peer_t *)socket->data;

  if (!peer || peer->state != HSK_STATE_CONNECTING)
    return;

  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  if (status != 0) {
    hsk_peer_log(peer, "failed connecting: %d\n", status);
    hsk_peer_destroy(peer);
    return;
  }

  peer->state = HSK_STATE_CONNECTED;
  hsk_peer_log(peer, "connected\n");

  status = uv_read_start((uv_stream_t *)socket, alloc_buffer, after_read);

  if (status != 0) {
    hsk_peer_log(peer, "failed reading: %d\n", status);
    hsk_peer_destroy(peer);
    return;
  }

  peer->state = HSK_STATE_READING;
  peer->conn_time = hsk_now();
}

static void
after_write(uv_write_t *req, int32_t status) {
  hsk_write_data_t *wd = (hsk_write_data_t *)req->data;
  hsk_peer_t *peer = wd->peer;
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  if (wd->should_free) {
    free(wd->data);
    wd->data = NULL;
  }

  free(wd);
  req->data = NULL;

  free(req);

  if (status != 0) {
    hsk_peer_log(peer, "write error: %d\n", status);
    hsk_peer_destroy(peer);
    return;
  }
}

static void
alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  hsk_peer_t *peer = (hsk_peer_t *)handle->data;

  if (!peer) {
    buf->base = NULL;
    buf->len = 0;
    return;
  }

  buf->base = (char *)peer->read_buffer;
  buf->len = HSK_BUFFER_SIZE;
}

static void
after_read(uv_stream_t *stream, long int nread, const uv_buf_t *buf) {
  hsk_peer_t *peer = (hsk_peer_t *)stream->data;

  if (!peer)
    return;

  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  if (nread < 0) {
    if (nread != UV_EOF)
      hsk_peer_log(peer, "read error: %s\n", uv_strerror(nread));
    hsk_peer_destroy(peer);
    return;
  }

  hsk_peer_on_read(peer, (uint8_t *)buf->base, (size_t)nread);
}

static void
after_close(uv_handle_t *handle) {
  hsk_peer_t *peer = (hsk_peer_t *)handle->data;
  assert(peer);
  handle->data = NULL;
  peer->state = HSK_STATE_DISCONNECTED;
  hsk_peer_log(peer, "closed peer\n");
  hsk_peer_free(peer);
}

static void
after_timer(uv_timer_t *timer) {
  hsk_pool_t *pool = (hsk_pool_t *)timer->data;
  assert(pool);
  hsk_pool_timer(pool);
}
