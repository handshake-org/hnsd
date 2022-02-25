#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>

#include "addr.h"
#include "addrmgr.h"
#include "bio.h"
#include "bn.h"
#include "brontide.h"
#include "chain.h"
#include "constants.h"
#include "ec.h"
#include "error.h"
#include "hash.h"
#include "header.h"
#include "map.h"
#include "msg.h"
#include "proof.h"
#include "resource.h"
#include "timedata.h"
#include "pool.h"
#include "utils.h"
#include "uv.h"

#ifdef HSK_DEBUG_LOG
#define hsk_pool_debug hsk_pool_log
#define hsk_peer_debug hsk_peer_log
#else
#define hsk_pool_debug(...) do {} while (0)
#define hsk_peer_debug(...) do {} while (0)
#endif

/*
 * Types
 */

typedef struct hsk_write_data_s {
  hsk_peer_t *peer;
  void *data;
  bool should_free;
} hsk_write_data_t;

/*
 * Prototypes
 */

static hsk_peer_t *
hsk_peer_alloc(hsk_pool_t *pool, bool encrypted);

static void
hsk_peer_free(hsk_peer_t *peer);

static void
hsk_pool_log(hsk_pool_t *pool, const char *fmt, ...);

static int
hsk_pool_refill(hsk_pool_t *pool);

static void
hsk_peer_push(hsk_peer_t *peer);

static int
hsk_peer_open(hsk_peer_t *peer, const hsk_addr_t *addr);

static int
hsk_peer_close(hsk_peer_t *peer);

static void
hsk_peer_log(hsk_peer_t *peer, const char *fmt, ...);

static void
hsk_peer_remove(hsk_peer_t *peer);

static int
hsk_peer_destroy(hsk_peer_t *peer);

static int
hsk_peer_parse(hsk_peer_t * peer, const uint8_t *msg, size_t msg_len);

static int
hsk_peer_send_ping(hsk_peer_t *peer, uint64_t nonce);

static int
hsk_peer_send_getheaders(hsk_peer_t *peer, const uint8_t *stop);

static int
hsk_peer_send_getaddr(hsk_peer_t *peer);

static int
hsk_peer_send_getproof(
  hsk_peer_t *peer,
  const uint8_t *name_hash,
  const uint8_t *root
);

static void
on_connect(uv_connect_t *conn, int status);

static void
alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf);

static void
after_write(uv_write_t *req, int status);

static void
after_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);

static void
after_close(uv_handle_t *handle);

static void
after_timer(uv_timer_t *timer);

void
hsk_chain_get_locator(hsk_chain_t *chain, hsk_getheaders_msg_t *msg);

static void
after_brontide_connect(const void *arg);

static void
after_brontide_read(const void *arg, const uint8_t *data, size_t data_len);

static int
brontide_do_write(
  const void *arg,
  const uint8_t *data,
  size_t data_len,
  bool is_heap
);

/*
 * Pool
 */

int
hsk_pool_init(hsk_pool_t *pool, const uv_loop_t *loop) {
  if (!pool || !loop)
    return HSK_EBADARGS;

  hsk_ec_t *ec = hsk_ec_alloc();

  if (!ec)
    return HSK_ENOMEM;

  if (!hsk_ec_create_privkey(ec, pool->key_))
    return HSK_EFAILURE;

  if (!hsk_ec_create_pubkey(ec, pool->key_, pool->pubkey))
    return HSK_EFAILURE;

  pool->loop = (uv_loop_t *)loop;
  pool->ec = ec;
  pool->key = &pool->key_[0];
  hsk_timedata_init(&pool->td);
  hsk_chain_init(&pool->chain, &pool->td);
  hsk_addrman_init(&pool->am, &pool->td);
  pool->timer = NULL;
  pool->peer_id = 0;
  hsk_map_init_map(&pool->peers, hsk_addr_hash, hsk_addr_equal, NULL);
  pool->head = NULL;
  pool->tail = NULL;
  pool->size = 0;
  pool->max_size = HSK_POOL_SIZE;
  pool->pending = NULL;
  pool->pending_count = 0;
  pool->block_time = 0;
  pool->getheaders_time = 0;
  pool->user_agent = (char *)malloc(256);
  strcpy(pool->user_agent, HSK_USER_AGENT);

  return HSK_SUCCESS;
}

void
hsk_pool_uninit(hsk_pool_t *pool) {
  if (!pool)
    return;

  if (pool->ec) {
    hsk_ec_free(pool->ec);
    pool->ec = NULL;
  }

  hsk_peer_t *peer, *next;
  for (peer = pool->head; peer; peer = next) {
    next = peer->next;
    hsk_peer_destroy(peer);
  }

  hsk_tld_req_t *req, *n;
  for (req = pool->pending; req; req = n) {
    n = req->next;
    free(req);
  }

  pool->pending = NULL;
  pool->pending_count = 0;

  hsk_map_uninit(&pool->peers);
  hsk_chain_uninit(&pool->chain);
  hsk_addrman_uninit(&pool->am);
  hsk_timedata_uninit(&pool->td);

  if (pool->user_agent) {
    free(pool->user_agent);
    pool->user_agent = NULL;
  }
}

bool
hsk_pool_set_key(hsk_pool_t *pool, const uint8_t *key) {
  assert(pool);

  if (!key) {
    memset(pool->key_, 0x00, 32);
    pool->key = NULL;
    memset(pool->pubkey, 0x00, sizeof(pool->pubkey));
    return true;
  }

  if (!hsk_ec_create_pubkey(pool->ec, key, pool->pubkey))
    return false;

  memcpy(&pool->key_[0], key, 32);
  pool->key = &pool->key_[0];

  return true;
}

bool
hsk_pool_set_size(hsk_pool_t *pool, int max_size) {
  assert(pool);

  if (max_size <= 0 || max_size > 1000)
    return false;

  pool->max_size = max_size;

  return true;
}

bool
hsk_pool_set_seeds(hsk_pool_t *pool, const char *seeds) {
  assert(pool);

  if (!seeds)
    return true;

  size_t len = strlen(seeds);
  int start = 0;
  int i;

  char seed[HSK_MAX_HOST + 1];
  hsk_addr_t addr;

  for (i = 0; i < len + 1; i++) {
    if (seeds[i] == ',' || seeds[i] == '\0') {
      size_t size = i - start;

      if (size == 0) {
        start = i + 1;
        continue;
      }

      if (size >= HSK_MAX_HOST) {
        hsk_pool_log(pool, "seed address exceeds maximum length allowed.\n");
        continue;
      }

      memcpy(&seed[0], &seeds[start], size);
      seed[size] = '\0';

      if (!hsk_addr_from_string(&addr, seed, 0)) {
        hsk_pool_log(pool, "could not parse seed from string: %s\n", seed);
        continue;
      }

      if (!hsk_addrman_add_addr(&pool->am, &addr)) {
        hsk_pool_log(pool, "could not add seed: %s\n", seed);
        continue;
      }

      start = i + 1;
    }
  }

  return true;
}

bool
hsk_pool_set_agent(hsk_pool_t *pool, const char *user_agent) {
  assert(pool);

  if (!user_agent)
    return true;

  size_t len = strlen(pool->user_agent);
  len += strlen(user_agent);

  // Agent size in p2p version message is 1 byte
  if (len > 0xff)
    return false;

  pool->user_agent = strcat(pool->user_agent, user_agent);

  return true;
}

hsk_pool_t *
hsk_pool_alloc(const uv_loop_t *loop) {
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

int
hsk_pool_open(hsk_pool_t *pool) {
  if (!pool)
    return HSK_EBADARGS;

  pool->timer = malloc(sizeof(uv_timer_t));
  if (!pool->timer)
    return HSK_ENOMEM;

  pool->timer->data = (void *)pool;

  if (uv_timer_init(pool->loop, pool->timer) != 0)
    return HSK_EFAILURE;

  if (uv_timer_start(pool->timer, after_timer, 3000, 3000) != 0)
    return HSK_EFAILURE;

  hsk_pool_log(pool, "pool opened (size=%u)\n", pool->max_size);

  hsk_pool_refill(pool);

  return HSK_SUCCESS;
}

int
hsk_pool_close(hsk_pool_t *pool) {
  if (!pool)
    return HSK_EBADARGS;

  if (uv_timer_stop(pool->timer) != 0)
    return HSK_EFAILURE;

  hsk_uv_close_free((uv_handle_t*)pool->timer);
  pool->timer = NULL;

  return HSK_SUCCESS;
}

int
hsk_pool_destroy(hsk_pool_t *pool) {
  if (!pool)
    return HSK_EBADARGS;

  int rc = hsk_pool_close(pool);
  if (rc != HSK_SUCCESS) {
    hsk_pool_log(pool, "failed to close pool: %s\n", hsk_strerror(rc));
    return rc;
  }

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

static bool
hsk_pool_getaddr(hsk_pool_t *pool, hsk_addr_t *addr) {
  return hsk_addrman_pick_addr(&pool->am, &pool->peers, addr);
}

static int
hsk_pool_refill(hsk_pool_t *pool) {
  if (pool->size < pool->max_size) {
    hsk_addr_t addr;

    if (!hsk_pool_getaddr(pool, &addr)) {
      hsk_pool_debug(pool, "could not find suitable addr\n");
      return HSK_SUCCESS;
    }

    if (hsk_addr_has_key(&addr) && !hsk_ec_verify_pubkey(pool->ec, addr.key)) {
      hsk_addrman_remove_addr(&pool->am, &addr);
      return HSK_SUCCESS;
    }

    hsk_peer_t *peer = hsk_peer_alloc(pool, hsk_addr_has_key(&addr));

    if (!peer) {
      hsk_pool_log(pool, "could not allocate peer\n");
      return HSK_ENOMEM;
    }

    hsk_addrman_mark_attempt(&pool->am, &addr);

    int rc = hsk_peer_open(peer, &addr);

    if (rc != HSK_SUCCESS) {
      hsk_peer_destroy(peer);
      return rc;
    }

    hsk_peer_push(peer);
  }

  return HSK_SUCCESS;
}

static hsk_peer_t *
hsk_pool_pick_prover(hsk_pool_t *pool, const uint8_t *name_hash) {
  hsk_peer_t *first_best = pool->head;
  hsk_peer_t *second_best = NULL;
  hsk_peer_t *deterministic = NULL;
  hsk_peer_t *random = NULL;

  int total = 0;

  hsk_peer_t *peer;
  for (peer = pool->head; peer; peer = peer->next) {
    if (peer->state != HSK_STATE_HANDSHAKE)
      continue;

    if (peer->proofs > first_best->proofs
        && peer->names.size <= first_best->names.size) {
      second_best = first_best;
      first_best = peer;
    }

    total += 1;
  }

  if (total == 0)
    return NULL;

  int i = name_hash[0] % total;
  int r = hsk_random() % total;

  for (peer = pool->head; peer; peer = peer->next) {
    if (peer->state != HSK_STATE_HANDSHAKE)
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

int
hsk_pool_resolve(
  hsk_pool_t *pool,
  const uint8_t *tld,
  hsk_resolve_cb callback,
  const void *arg
) {
  char namestr[HSK_DNS_MAX_NAME_STRING] = {0};
  assert(hsk_dns_name_to_string(tld, namestr));
  hsk_pool_log(pool, "sending proof request for: %s\n", namestr);

  if (!hsk_chain_synced(&pool->chain)) {
    hsk_pool_log(pool, "cannot send proof request: chain not synced.\n");
    return HSK_ETIMEOUT;
  }

  const uint8_t *root = hsk_chain_safe_root(&pool->chain);
  hsk_tld_req_t *req = malloc(sizeof(hsk_tld_req_t));

  if (!req)
    return HSK_ENOMEM;

  // Copy length byte, label bytes, and terminal 0x00 (".")
  memcpy(req->tld, tld, tld[0] + 2);

  hsk_hash_tld(tld, req->hash);

  memcpy(req->root, root, 32);

  req->callback = callback;
  req->arg = (void *)arg;
  req->time = hsk_now();
  req->next = NULL;

  hsk_peer_t *peer = hsk_pool_pick_prover(pool, req->hash);

  // Insert into a "pending" list.
  if (!peer) {
    hsk_pool_log(pool, "cannot send proof request: no peer.\n");
    req->next = pool->pending;
    pool->pending = req;
    pool->pending_count += 1;
    return HSK_SUCCESS;
  }

  hsk_tld_req_t *head = hsk_map_get(&peer->names, req->hash);

  if (!hsk_map_set(&peer->names, req->hash, (void *)req)) {
    free(req);
    return HSK_ENOMEM;
  }

  if (head) {
    hsk_peer_log(peer, "already requesting proof for: %s\n", namestr);
    req->next = head;
    req->time = head->time;
    return HSK_SUCCESS;
  }

  hsk_peer_log(peer, "sending proof request for: %s\n", namestr);

  return hsk_peer_send_getproof(peer, req->hash, root);
}

static void
hsk_pool_resend(hsk_pool_t *pool) {
  if (!hsk_chain_synced(&pool->chain))
    return;

  uint8_t *root = pool->chain.tip->name_root;
  hsk_tld_req_t *req = pool->pending;

  if (!req)
    return;

  hsk_peer_t *peer = hsk_pool_pick_prover(pool, req->hash);

  if (!peer)
    return;

  hsk_tld_req_t *next;

  pool->pending = NULL;
  pool->pending_count = 0;

  int64_t now = hsk_now();

  for (; req; req = next) {
    next = req->next;

    hsk_peer_t *peer = hsk_pool_pick_prover(pool, req->hash);
    assert(peer);

    req->next = NULL;
    req->time = now;

    hsk_tld_req_t *head = hsk_map_get(&peer->names, req->hash);

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
    if (peer->state != HSK_STATE_HANDSHAKE)
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

    hsk_tld_req_t *req = (hsk_tld_req_t *)hsk_map_value(map, i);
    assert(req);

    hsk_tld_req_t *tail;
    int count = 0;

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
    hsk_tld_req_t *req, *next;

    for (req = pool->pending; req; req = next) {
      next = req->next;

      req->callback(
        (uint8_t *)req->tld,
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

    hsk_tld_req_t *req = (hsk_tld_req_t *)hsk_map_value(map, i);
    hsk_tld_req_t *next;

    assert(req);

    hsk_map_delete(map, i);

    for (; req; req = next) {
      next = req->next;

      req->callback(
        (uint8_t *)req->tld,
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

    hsk_tld_req_t *req = (hsk_tld_req_t *)hsk_map_value(map, i);
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

    if (peer->state != HSK_STATE_HANDSHAKE)
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
        hsk_peer_debug(peer, "pinging...\n");
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

static int
hsk_peer_init(hsk_peer_t *peer, hsk_pool_t *pool, bool encrypted) {
  if (!peer || !pool)
    return HSK_EBADARGS;

  assert(pool && pool->loop);

  peer->pool = (void *)pool;
  peer->chain = &pool->chain;
  peer->loop = pool->loop;
  // peer->socket;

  peer->brontide = NULL;
  if (encrypted) {
    peer->brontide = malloc(sizeof(hsk_brontide_t));

    if (!peer->brontide)
      goto fail;

    hsk_brontide_init(peer->brontide, pool->ec);
    peer->brontide->connect_cb = after_brontide_connect;
    peer->brontide->connect_arg = (void *)peer;
    peer->brontide->write_cb = brontide_do_write;
    peer->brontide->write_arg = (void *)peer;
    peer->brontide->read_cb = after_brontide_read;
    peer->brontide->read_arg = (void *)peer;
  }

  peer->id = pool->peer_id++;
  memset(peer->host, 0, sizeof(peer->host));
  hsk_addr_init(&peer->addr);
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
  peer->msg = (uint8_t *)malloc(9);
  peer->msg_pos = 0;
  peer->msg_len = 9;
  peer->msg_cmd = 0;
  peer->next = NULL;

  if (!peer->msg)
    goto fail;

  return HSK_SUCCESS;

fail:
  if (peer->brontide) {
    hsk_brontide_uninit(peer->brontide);
    free(peer->brontide);
    peer->brontide = NULL;
  }

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

  if (peer->brontide != NULL) {
    hsk_brontide_uninit(peer->brontide);
    free(peer->brontide);
    peer->brontide = NULL;
  }

  hsk_map_uninit(&peer->names);

  if (peer->msg) {
    free(peer->msg);
    peer->msg = NULL;
  }
}

static hsk_peer_t *
hsk_peer_alloc(hsk_pool_t *pool, bool encrypted) {
  hsk_peer_t *peer = malloc(sizeof(hsk_peer_t));

  if (!peer)
    return NULL;

  if (hsk_peer_init(peer, pool, encrypted) != HSK_SUCCESS) {
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

static int
hsk_peer_open(hsk_peer_t *peer, const hsk_addr_t *addr) {
  assert(peer && addr);
  assert(peer->pool && peer->loop && peer->state == HSK_STATE_DISCONNECTED);

  peer->state = HSK_STATE_CONNECTING;

  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;
  uv_loop_t *loop = pool->loop;

  if (uv_tcp_init(loop, &peer->socket) != 0)
    return HSK_EFAILURE;

  peer->socket.data = (void *)peer;

  hsk_addr_copy(&peer->addr, addr);

  if (!hsk_addr_to_string(addr, peer->host, HSK_MAX_HOST, HSK_BRONTIDE_PORT))
    return HSK_EBADARGS;

  uv_connect_t *conn = malloc(sizeof(uv_connect_t));

  if (!conn)
    return HSK_ENOMEM;

  struct sockaddr_storage ss;
  struct sockaddr *sa = (struct sockaddr *)&ss;

  assert(hsk_addr_to_sa(addr, sa));

  if (peer->brontide != NULL)
    assert(hsk_brontide_connect(peer->brontide, pool->key, addr->key) == 0);

  if (uv_tcp_connect(conn, &peer->socket, sa, on_connect) != 0) {
    free(conn);
    return HSK_EFAILURE;
  }

  hsk_peer_t *peerIter, *next;
  uint64_t active = 0;
  for (peerIter = pool->head; peerIter; peerIter = next) {
    next = peerIter->next;
    if (peerIter->state == HSK_STATE_HANDSHAKE)
      active++;
  }
  hsk_pool_log(pool, "size: %d active: %d\n", pool->size, active);

  return HSK_SUCCESS;
}

static int
hsk_peer_close(hsk_peer_t *peer) {
  switch (peer->state) {
    case HSK_STATE_DISCONNECTING:
      return HSK_SUCCESS;
    case HSK_STATE_HANDSHAKE:
      if (peer->brontide != NULL)
        hsk_brontide_destroy(peer->brontide);
    case HSK_STATE_READING:
      assert(uv_read_stop((uv_stream_t *)&peer->socket) == 0);
    case HSK_STATE_CONNECTED:
    case HSK_STATE_CONNECTING:
      uv_close((uv_handle_t *)&peer->socket, after_close);
      hsk_peer_log(peer, "closing peer\n");
      break;
    case HSK_STATE_DISCONNECTED:
      hsk_peer_log(peer, "closed peer (never opened)\n");
      hsk_peer_remove(peer);
      hsk_peer_free(peer);
      return HSK_SUCCESS;
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

static int
hsk_peer_destroy(hsk_peer_t *peer) {
  return hsk_peer_close(peer);
}

static void
hsk_peer_log(hsk_peer_t *peer, const char *fmt, ...) {
  printf("peer %" PRIu64 " (%s): ", peer->id, peer->host);

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

  assert(!hsk_map_has(&pool->peers, &peer->addr));
  hsk_map_set(&pool->peers, &peer->addr, peer);
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
    assert(pool->size > 0);
    pool->size -= 1;
    assert(hsk_map_del(&pool->peers, &peer->addr));
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

  assert(pool->size > 0);
  pool->size -= 1;

  assert(hsk_map_del(&pool->peers, &peer->addr));
}

static int
hsk_peer_write_raw(
  hsk_peer_t *peer,
  uint8_t *data,
  size_t data_len,
  bool should_free
) {
  if (peer->state == HSK_STATE_DISCONNECTING)
    return HSK_SUCCESS;

  int rc = HSK_SUCCESS;
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
    { .base = (char *)data, .len = data_len }
  };

  int status = uv_write(req, stream, bufs, 1, after_write);

  if (status != 0) {
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

  if (data && should_free)
    free(data);

  return rc;
}

static int
hsk_peer_write(
  hsk_peer_t *peer,
  uint8_t *data,
  size_t data_len,
  bool should_free
) {
  if (peer->state != HSK_STATE_HANDSHAKE)
    return HSK_SUCCESS;

  assert(should_free);

  int rc;
  if (peer->brontide != NULL) {
    rc = hsk_brontide_write(peer->brontide, data, data_len);
  } else {
    rc = hsk_peer_write_raw(peer, data, data_len, true);
 }
  return rc;
}

static int
hsk_peer_send(hsk_peer_t *peer, const hsk_msg_t *msg) {
  int msg_size = hsk_msg_size(msg);
  assert(msg_size != -1);

  size_t size = 9 + msg_size;
  uint8_t *data = malloc(size);

  if (!data)
    return HSK_ENOMEM;

  uint8_t *buf = data;

  // Magic Number
  write_u32(&buf, HSK_MAGIC);

  // Command
  write_u8(&buf, msg->cmd);

  // Msg Size
  write_u32(&buf, msg_size);

  // Msg
  hsk_msg_write(msg, &buf);

  return hsk_peer_write(peer, data, size, true);
}

static int
hsk_peer_send_version(hsk_peer_t *peer) {
  hsk_peer_log(peer, "sending version\n");
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  hsk_version_msg_t msg = { .cmd = HSK_MSG_VERSION };
  hsk_msg_init((hsk_msg_t *)&msg);

  msg.version = HSK_PROTO_VERSION;
  msg.services = HSK_SERVICES;
  msg.time = hsk_timedata_now(&pool->td);

  const hsk_addrentry_t *entry = hsk_addrman_get(&pool->am, &peer->addr);

  if (entry) {
    msg.remote.time = entry->time;
    msg.remote.services = entry->services;
  }

  hsk_addr_copy(&msg.remote.addr, &peer->addr);

  msg.nonce = hsk_nonce();
  strcpy(msg.agent, pool->user_agent);
  msg.height = (uint32_t)pool->chain.height;

  peer->version_time = hsk_now();

  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int
hsk_peer_send_verack(hsk_peer_t *peer) {
  hsk_peer_log(peer, "sending verack\n");
  hsk_version_msg_t msg = { .cmd = HSK_MSG_VERACK };
  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int
hsk_peer_send_ping(hsk_peer_t *peer, uint64_t nonce) {
  hsk_ping_msg_t msg = {
    .cmd = HSK_MSG_PING,
    .nonce = nonce
  };
  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int
hsk_peer_send_pong(hsk_peer_t *peer, uint64_t nonce) {
  hsk_pong_msg_t msg = {
    .cmd = HSK_MSG_PONG,
    .nonce = nonce
  };
  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int
hsk_peer_send_sendheaders(hsk_peer_t *peer) {
  hsk_peer_log(peer, "sending sendheaders\n");
  hsk_version_msg_t msg = { .cmd = HSK_MSG_SENDHEADERS };
  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int
hsk_peer_send_getaddr(hsk_peer_t *peer) {
  hsk_peer_log(peer, "sending getaddr\n");
  hsk_version_msg_t msg = { .cmd = HSK_MSG_GETADDR };
  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int
hsk_peer_send_getheaders(hsk_peer_t *peer, const uint8_t *stop) {
  hsk_peer_log(peer, "sending getheaders\n");
  hsk_getheaders_msg_t msg = { .cmd = HSK_MSG_GETHEADERS };

  hsk_msg_init((hsk_msg_t *)&msg);

  hsk_chain_get_locator(peer->chain, &msg);

  if (stop)
    memcpy(msg.stop, stop, 32);

  peer->getheaders_time = hsk_now();

  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int
hsk_peer_send_getproof(
  hsk_peer_t *peer,
  const uint8_t *name_hash,
  const uint8_t *root
) {
  hsk_getproof_msg_t msg = { .cmd = HSK_MSG_GETPROOF };
  hsk_msg_init((hsk_msg_t *)&msg);

  memcpy(msg.key, name_hash, 32);
  memcpy(msg.root, root, 32);

  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int
hsk_peer_handle_version(hsk_peer_t *peer, const hsk_version_msg_t *msg) {
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  hsk_peer_log(peer, "received version: %s (%u)\n", msg->agent, msg->height);
  peer->height = (int64_t)msg->height;

  hsk_timedata_add(&pool->td, &peer->addr, msg->time);
  hsk_addrman_mark_ack(&pool->am, &peer->addr, msg->services);

  hsk_peer_send_verack(peer);

  // At this point, we've sent a version and received VERACK.
  // The peer sent us their version and we sent back a VERACK.
  // The handshake is complete, start syncing.
  int rc = hsk_peer_send_sendheaders(peer);

  if (rc != HSK_SUCCESS)
    return rc;

  // Discover more peers
  rc = hsk_peer_send_getaddr(peer);

  if (rc != HSK_SUCCESS)
    return rc;

  // Start syncing
  return hsk_peer_send_getheaders(peer, NULL);
}

static int
hsk_peer_handle_verack(hsk_peer_t *peer, const hsk_verack_msg_t *msg) {
  hsk_peer_log(peer, "received verack\n");

  peer->version_time = 0;

  // VERACK is boring, no need to respond.
  return HSK_SUCCESS;
}

static int
hsk_peer_handle_ping(hsk_peer_t *peer, const hsk_ping_msg_t *msg) {
  return hsk_peer_send_pong(peer, msg->nonce);
}

static int
hsk_peer_handle_pong(hsk_peer_t *peer, const hsk_pong_msg_t *msg) {
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

  hsk_peer_debug(peer, "received pong\n");

  int64_t now = hsk_now();

  if (now >= peer->last_ping) {
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

static int
hsk_peer_handle_addr(hsk_peer_t *peer, hsk_addr_msg_t *msg) {
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  if (msg->addr_count > 1000)
    return HSK_EFAILURE;

  hsk_peer_log(peer, "received %u addrs\n", msg->addr_count);

  int64_t now = hsk_timedata_now(&pool->td);

  int i;
  for (i = 0; i < msg->addr_count; i++) {
    hsk_netaddr_t *addr = &msg->addrs[i];

    if (!hsk_addr_is_routable(&addr->addr))
      continue;

    if (!(addr->services & 1))
      continue;

    if (addr->time <= 100000000 || addr->time > now + 10 * 60)
      addr->time = now - 5 * 24 * 60 * 60;

    if (addr->addr.port == 0)
      continue;

    if (hsk_addr_has_key(&addr->addr))
      continue;

    hsk_addrman_add_na(&pool->am, addr);
  }

  return HSK_SUCCESS;
}

static int
hsk_peer_handle_headers(hsk_peer_t *peer, const hsk_headers_msg_t *msg) {
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  hsk_peer_log(peer, "received %u headers\n", msg->header_count);

  if (msg->header_count == 0)
    return HSK_SUCCESS;

  if (msg->header_count > 2000)
    return HSK_EFAILURE;

  const uint8_t *last = NULL;
  hsk_header_t *hdr;

  for (hdr = msg->headers; hdr; hdr = hdr->next) {
    if (last && memcmp(hdr->prev_block, last, 32) != 0) {
      hsk_peer_log(peer, "invalid header chain\n");
      return HSK_EHASHMISMATCH;
    }

    last = hsk_header_cache(hdr);

    int rc = hsk_header_verify_pow(hdr);

    if (rc != HSK_SUCCESS) {
      hsk_peer_log(peer, "invalid header pow\n");
      return rc;
    }
  }

  bool orphan = false;

  for (hdr = msg->headers; hdr; hdr = hdr->next) {
    int rc = hsk_chain_add(peer->chain, hdr);

    if (rc == HSK_ETIMETOOOLD || rc == HSK_EBADDIFFBITS) {
      hsk_peer_log(peer, "failed adding block: %s\n", hsk_strerror(rc));

      if (!hsk_addrman_add_ban(&pool->am, &peer->addr))
        return HSK_ENOMEM;

      hsk_peer_destroy(peer);
      return rc;
    }

    if (rc == HSK_ETIMETOONEW) {
      hsk_peer_log(peer, "failed adding block: %s\n", hsk_strerror(rc));
      hsk_peer_destroy(peer);
      return rc;
    }

    if (rc == HSK_EORPHAN || rc == HSK_EDUPLICATEORPHAN) {
      if (!orphan)
        hsk_peer_log(peer, "failed adding orphan\n");
      orphan = true;
      continue;
    }

    if (rc != HSK_SUCCESS) {
      hsk_peer_log(peer, "failed adding block: %s\n", hsk_strerror(rc));
      if (rc == HSK_EDUPLICATE)
        return HSK_SUCCESS;
      else
        return rc;
    }

    peer->headers += 1;
  }

  if (orphan) {
    hsk_header_t *hdr = msg->headers;
    const uint8_t *hash = hsk_header_cache(hdr);
    hsk_peer_log(peer, "peer sent orphan: %s\n", hsk_hex_encode32(hash));
    hsk_peer_log(peer, "peer sending orphan locator\n");
    hsk_peer_send_getheaders(peer, NULL);
    return HSK_SUCCESS;
  }

  pool->block_time = hsk_now();
  peer->getheaders_time = 0;

  if (msg->header_count == 2000) {
    hsk_peer_log(peer, "requesting more headers\n");
    return hsk_peer_send_getheaders(peer, NULL);
  }

  return HSK_SUCCESS;
}

static int
hsk_peer_handle_proof(hsk_peer_t *peer, const hsk_proof_msg_t *msg) {
  hsk_peer_log(peer, "received proof: %s\n", hsk_hex_encode32(msg->key));

  hsk_tld_req_t *reqs = hsk_map_get(&peer->names, msg->key);

  if (!reqs) {
    hsk_peer_log(peer,
      "received unsolicited proof: %s\n",
      hsk_hex_encode32(msg->key));
    return HSK_EBADARGS;
  }

  char namestr[HSK_DNS_MAX_NAME_STRING] = {0};
  assert(hsk_dns_name_to_string(reqs->tld, namestr));
  hsk_peer_log(peer, "received proof for: %s\n", namestr);

  if (memcmp(msg->root, reqs->root, 32) != 0) {
    hsk_peer_log(peer, "proof hash mismatch (why?)\n");
    return HSK_EHASHMISMATCH;
  }

  bool exists;
  uint8_t *data;
  size_t data_len;

  int rc = hsk_proof_verify(
    msg->root,
    msg->key,
    &msg->proof,
    &exists,
    &data,
    &data_len
  );

  if (rc != HSK_SUCCESS) {
    hsk_peer_log(peer, "invalid proof: %s\n", hsk_strerror(rc));
    return rc;
  }

  hsk_map_del(&peer->names, msg->key);

  hsk_tld_req_t *req, *next;

  for (req = reqs; req; req = next) {
    next = req->next;

    req->callback(
      (uint8_t *)req->tld,
      HSK_SUCCESS,
      exists,
      data,
      data_len,
      req->arg
    );

    free(req);
  }

  free(data);

  peer->proofs += 1;

  return HSK_SUCCESS;
}

static int
hsk_peer_handle_msg(hsk_peer_t *peer, const hsk_msg_t *msg) {
  hsk_peer_debug(peer, "handling msg: %s\n", hsk_msg_str(msg->cmd));

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
      hsk_peer_debug(peer, "cannot handle getaddr\n");
      return HSK_SUCCESS;
    }
    case HSK_MSG_ADDR: {
      return hsk_peer_handle_addr(peer, (hsk_addr_msg_t *)msg);
    }
    case HSK_MSG_GETHEADERS: {
      hsk_peer_debug(peer, "cannot handle getheaders\n");
      return HSK_SUCCESS;
    }
    case HSK_MSG_HEADERS: {
      return hsk_peer_handle_headers(peer, (hsk_headers_msg_t *)msg);
    }
    case HSK_MSG_SENDHEADERS: {
      hsk_peer_debug(peer, "cannot handle sendheaders\n");
      return HSK_SUCCESS;
    }
    case HSK_MSG_GETPROOF: {
      hsk_peer_debug(peer, "cannot handle getproof\n");
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
hsk_peer_on_read(hsk_peer_t *peer, const uint8_t *data, size_t data_len) {
  if (peer->state != HSK_STATE_HANDSHAKE)
    return;

  peer->last_recv = hsk_now();

  while (peer->msg_pos + data_len >= peer->msg_len) {
    assert(peer->msg_pos <= peer->msg_len);
    size_t need = peer->msg_len - peer->msg_pos;
    memcpy(peer->msg + peer->msg_pos, data, need);
    data += need;
    data_len -= need;
    if (hsk_peer_parse(peer, peer->msg, peer->msg_len) != 0) {
      hsk_peer_destroy(peer);
      return;
    }
  }

  memcpy(peer->msg + peer->msg_pos, data, data_len);
  peer->msg_pos += data_len;
}

static int
hsk_peer_parse_hdr(hsk_peer_t *peer, const uint8_t *msg, size_t msg_len) {
  uint32_t magic;
  uint8_t *ms = (uint8_t *)msg;

  if (!read_u32(&ms, &msg_len, &magic)) {
    hsk_peer_log(peer, "invalid header\n");
    return HSK_EENCODING;
  }

  if (magic != HSK_MAGIC) {
    hsk_peer_log(peer, "invalid magic: %x\n", magic);
    return HSK_EENCODING;
  }

  uint8_t cmd;

  if (!read_u8(&ms, &msg_len, &cmd)) {
    hsk_peer_log(peer, "invalid command\n");
    return HSK_EENCODING;
  }

  const char *str = hsk_msg_str(cmd);

  uint32_t size;

  if (!read_u32(&ms, &msg_len, &size)) {
    hsk_peer_log(peer, "invalid header: %s\n", str);
    return HSK_EENCODING;
  }

  if (size > HSK_MAX_MESSAGE) {
    hsk_peer_log(peer, "invalid msg size: %s - %u\n", str, size);
    return HSK_EENCODING;
  }

  uint8_t *slab = realloc(peer->msg, size);

  if (!slab && size != 0)
    return HSK_ENOMEM;

  peer->msg_hdr = true;
  peer->msg = slab;
  peer->msg_pos = 0;
  peer->msg_len = size;
  peer->msg_cmd = cmd;

  hsk_peer_debug(peer, "received header: %s\n", str);
  hsk_peer_debug(peer, "  msg size: %u\n", peer->msg_len);

  return HSK_SUCCESS;
}

static int
hsk_peer_parse(hsk_peer_t *peer, const uint8_t *msg, size_t msg_len) {
  if (!peer->msg_hdr)
    return hsk_peer_parse_hdr(peer, msg, msg_len);

  int rc = HSK_SUCCESS;
  const char *str = hsk_msg_str(peer->msg_cmd);

  if (strcmp(str, "unknown") == 0) {
    hsk_peer_log(peer, "unknown command: %u\n", peer->msg_cmd);
    goto done;
  }

  hsk_msg_t *m = hsk_msg_alloc(peer->msg_cmd);

  if (!m) {
    rc = HSK_ENOMEM;
    goto done;
  }

  if (!hsk_msg_decode(msg, msg_len, m)) {
    hsk_peer_log(peer, "error parsing msg: %s\n", str);
    free(m);
    rc = HSK_EENCODING;
    goto done;
  }

  rc = hsk_peer_handle_msg(peer, m);
  hsk_msg_free(m);

done: ;
  uint8_t *slab = realloc(peer->msg, 9);

  if (!slab)
    return HSK_ENOMEM;

  peer->msg_hdr = false;
  peer->msg = slab;
  peer->msg_pos = 0;
  peer->msg_len = 9;
  peer->msg_cmd = 0;

  return rc;
}

/*
 * UV behavior
 */

static void
on_connect(uv_connect_t *conn, int status) {
  uv_tcp_t *socket = (uv_tcp_t *)conn->handle;
  free(conn);

  hsk_peer_t *peer = (hsk_peer_t *)socket->data;

  if (!peer || peer->state != HSK_STATE_CONNECTING)
    return;

  if (status != 0) {
    hsk_peer_log(peer, "failed connecting: %s\n", uv_strerror(status));
    hsk_peer_destroy(peer);
    return;
  }

  peer->state = HSK_STATE_CONNECTED;
  hsk_peer_log(peer, "connected\n");

  status = uv_read_start((uv_stream_t *)socket, alloc_buffer, after_read);

  if (status != 0) {
    hsk_peer_log(peer, "failed reading: %s\n", uv_strerror(status));
    hsk_peer_destroy(peer);
    return;
  }

  peer->state = HSK_STATE_READING;
  peer->conn_time = hsk_now();

  if (peer->brontide != NULL) {
    int r = hsk_brontide_on_connect(peer->brontide);

    if (r != HSK_SUCCESS) {
      hsk_peer_log(peer, "brontide_on_connect failed: %s\n", hsk_strerror(r));
      hsk_peer_destroy(peer);
      return;
    }
    return;
  }

  peer->state = HSK_STATE_HANDSHAKE;
  hsk_peer_send_version(peer);
}

static void
after_write(uv_write_t *req, int status) {
  hsk_write_data_t *wd = (hsk_write_data_t *)req->data;
  hsk_peer_t *peer = wd->peer;

  if (wd->data && wd->should_free) {
    free(wd->data);
    wd->data = NULL;
  }

  free(wd);
  req->data = NULL;

  free(req);

  if (status != 0) {
    hsk_peer_log(peer, "write error: %s\n", uv_strerror(status));
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
after_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
  hsk_peer_t *peer = (hsk_peer_t *)stream->data;

  if (!peer)
    return;
  
  if (nread < 0) {
    if (nread != UV_EOF)
      hsk_peer_log(peer, "read error: %s\n", uv_strerror(nread));
    hsk_peer_destroy(peer);
    return;
  }
  
  if (peer->brontide != NULL) {
    int r = hsk_brontide_on_read(
        peer->brontide,
        (uint8_t *)buf->base,
        (size_t)nread
        );
    if (r != HSK_SUCCESS) {
      hsk_peer_log(peer, "brontide_on_read failed: %s\n", hsk_strerror(r));
      hsk_peer_destroy(peer);
      return;
    }
  } else {
    hsk_peer_on_read(
        peer,
        (uint8_t *)buf->base,
        (size_t)nread
        );
  }
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

static void
after_brontide_connect(const void *arg) {
  hsk_peer_t *peer = (hsk_peer_t *)arg;
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  if (peer->state != HSK_STATE_READING)
    return;

  hsk_addrman_mark_success(&pool->am, &peer->addr);

  peer->state = HSK_STATE_HANDSHAKE;

  hsk_peer_send_version(peer);
}

static void
after_brontide_read(const void *arg, const uint8_t *data, size_t data_len) {
  hsk_peer_t *peer = (hsk_peer_t *)arg;
  hsk_peer_on_read(peer, data, data_len);
}

static int
brontide_do_write(
  const void *arg,
  const uint8_t *data,
  size_t data_len,
  bool is_heap
) {
  hsk_peer_t *peer = (hsk_peer_t *)arg;

  if (!is_heap) {
    uint8_t *buf = malloc(data_len);

    if (!buf)
      return HSK_ENOMEM;

    memcpy(buf, data, data_len);
    data = buf;
  }

  return hsk_peer_write_raw(peer, (uint8_t *)data, data_len, true);
}
