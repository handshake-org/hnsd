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
#include "utils.h"
#include "bn.h"
#include "pool.h"
#include "bio.h"
#include "msg.h"

/*
 * Types
 */

typedef struct {
  hsk_peer_t *peer;
  void *data;
  bool should_free;
} hsk_write_data_t;

typedef struct hsk_name_req_s {
  char name[256];
  uint8_t hash[32];
  uint8_t root[32];
  hsk_resolve_cb callback;
  void *arg;
  struct hsk_name_req_s *next;
} hsk_name_req_t;

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
hsk_peer_remove(hsk_peer_t *);

static int32_t
hsk_peer_destroy(hsk_peer_t *);

static int32_t
hsk_peer_parse(hsk_peer_t *, uint8_t *, size_t);

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
  hsk_map_init_hash_map(&pool->resolutions, free);

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

  hsk_map_clear(&pool->resolutions);

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

  hsk_pool_refill(pool);

  return HSK_SUCCESS;
}

int32_t
hsk_pool_close(hsk_pool_t *pool) {
  if (!pool)
    return HSK_EBADARGS;

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

static int32_t
hsk_pool_send_getproof(hsk_pool_t *pool, uint8_t *name_hash, uint8_t *root) {
  hsk_peer_t *peer = pool->head;

  if (!peer)
    return HSK_EBADARGS;

  return hsk_peer_send_getproof(peer, name_hash, root);
}

int32_t
hsk_pool_resolve(
  hsk_pool_t *pool,
  char *name,
  hsk_resolve_cb callback,
  void *arg
) {
  uint8_t *root = pool->chain.tip->trie_root;

  hsk_name_req_t *req = malloc(sizeof(hsk_name_req_t));

  if (!req)
    return HSK_ENOMEM;

  strcpy(req->name, name);

  hsk_hash_blake2b(name, strlen(name), req->hash);

  memcpy(req->root, root, 32);

  req->callback = callback;
  req->arg = arg;
  req->next = NULL;

  hsk_name_req_t *head = hsk_map_get(&pool->resolutions, req->hash);

  if (head)
    req->next = head;

  if (!hsk_map_set(&pool->resolutions, req->hash, (void *)req)) {
    free(req);
    return HSK_ENOMEM;
  }

  return hsk_pool_send_getproof(pool, req->hash, root);
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
  peer->socket = NULL;
  peer->id = pool->peer_id++;
  memset(peer->host, 0, sizeof(peer->host));
  peer->family = AF_INET;
  memset(peer->ip, 0, 16);
  peer->port = 0;
  peer->connected = false;
  peer->reading = false;
  memset(peer->read_buffer, 0, HSK_BUFFER_SIZE);
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

  hsk_peer_close(peer);

  if (peer->socket) {
    free(peer->socket);
    peer->socket = NULL;
  }

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
  assert(peer->pool && peer->loop && !peer->connected && !peer->socket);

  int32_t rc = HSK_SUCCESS;
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;
  uv_loop_t *loop = pool->loop;

  uv_tcp_t *socket = NULL;
  uv_connect_t *conn = NULL;

  // Socket is uv_stream_t, also a uv_handle_t -- ends up on conn->handle.
  socket = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));

  if (!socket) {
    rc = HSK_ENOMEM;
    goto fail;
  }

  // Conn is uv_req_t, contains socket.
  conn = (uv_connect_t *)malloc(sizeof(uv_connect_t));

  if (!conn) {
    rc = HSK_ENOMEM;
    goto fail;
  }

  if (uv_tcp_init(loop, socket) != 0) {
    rc = HSK_EFAILURE;
    goto fail;
  }

  // Make the peer reference the handle,
  // and the handle reference the peer.
  socket->data = (void *)peer;
  peer->socket = socket;

  if (!hsk_get_inet(addr, &peer->family, peer->ip, &peer->port)) {
    rc = HSK_EBADARGS;
    goto fail;
  }

  if (!hsk_inet2string(addr, peer->host, sizeof(peer->host) - 1, HSK_PORT)) {
    rc = HSK_EBADARGS;
    goto fail;
  }

  if (uv_tcp_connect(conn, socket, addr, on_connect) != 0) {
    rc = HSK_EFAILURE;
    goto fail;
  }

  return rc;

fail:
  if (socket)
    free(socket);

  if (conn)
    free(conn);

  return rc;
}

static int32_t
hsk_peer_close(hsk_peer_t *peer) {
  if (peer->reading) {
    assert(peer->socket);
    int32_t rc = uv_read_stop((uv_stream_t *)peer->socket);
    if (rc != 0)
      return rc;
    peer->reading = false;
  }

  if (peer->connected) {
    assert(peer->socket);
    uv_close((uv_handle_t *)peer->socket, NULL);
    peer->connected = false;
  }

  hsk_peer_remove(peer);

  return HSK_SUCCESS;
}

static int32_t
hsk_peer_destroy(hsk_peer_t *peer) {
  if (!peer)
    return HSK_EBADARGS;

  int32_t rc = hsk_peer_close(peer);

  if (rc != HSK_SUCCESS)
    return rc;

  if (peer->socket) {
    free(peer->socket);
    peer->socket = NULL;
  }

  if (peer->msg) {
    free(peer->msg);
    peer->msg = NULL;
  }

  free(peer);
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

  uv_stream_t *stream = (uv_stream_t *)peer->socket;

  uv_buf_t bufs[] = {
    { .base = data, .len = data_len }
  };

  int status = uv_write(req, stream, bufs, 1, after_write);

  if (status != 0) {
    hsk_pool_t *pool = (hsk_pool_t *)peer->pool;
    hsk_peer_log(peer, "failed writing: %d\n", status);
    hsk_peer_destroy(peer);
    hsk_pool_refill(pool);
    rc = HSK_EFAILURE;
    goto fail;
  }

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
  msg.services = 0;
  msg.time = hsk_now();

  if (theirs) {
    msg.remote.time = theirs->time;
    msg.remote.services = theirs->services;
  }

  msg.remote.type = 0;
  memcpy(msg.remote.addr, peer->ip, 16);
  msg.remote.port = peer->port;
  msg.nonce = 0;
  strcpy(msg.agent, HSK_USER_AGENT);
  msg.height = pool->chain.height;

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

  return hsk_peer_send_version(peer, msg);
}

static int32_t
hsk_peer_handle_verack(hsk_peer_t *peer, hsk_verack_msg_t *msg) {
  int32_t rc = hsk_peer_send_sendheaders(peer);

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
  hsk_peer_log(peer, "received pong\n");
  return HSK_SUCCESS;
}

static int32_t
hsk_peer_handle_addr(hsk_peer_t *peer, hsk_addr_msg_t *msg) {
  hsk_peer_log(peer, "received %d addrs\n", msg->addr_count);
  // int32_t i;
  // for (i = 0; i < m->addr_count; i++)
  //   hsk_addr_t *addr = &m->addrs[i];
  return HSK_SUCCESS;
}

static int32_t
hsk_peer_handle_headers(hsk_peer_t *peer, hsk_headers_msg_t *msg) {
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
  }

  if (msg->header_count == 2000) {
    hsk_peer_log(peer, "requesting more headers\n");
    return hsk_peer_send_getheaders(peer, NULL);
  }

  return HSK_SUCCESS;
}

static int32_t
hsk_peer_handle_proof(hsk_peer_t *peer, hsk_proof_msg_t *msg) {
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  hsk_peer_log(peer, "received proof\n");

  if (msg->data_len > 512) {
    hsk_peer_log(peer, "invalid proof data\n");
    return HSK_EBADARGS;
  }

  hsk_name_req_t *reqs = hsk_map_get(&pool->resolutions, msg->name_hash);

  if (!reqs) {
    hsk_peer_log(peer, "received unsolicited proof\n");
    return HSK_EBADARGS;
  }

  if (memcmp(msg->root, reqs->root, 32) != 0) {
    hsk_peer_log(peer, "proof hash mismatch\n");
    return HSK_EHASHMISMATCH;
  }

  uint8_t *dhash;
  size_t dhash_len;

  // TODO: Verify length in function.
  // Have return pointer so dhash can be stack allocated.
  // Add extra arg for bool *exists
  // Make it a consensus rule that 0-length records cannot exist.
  int32_t rc = hsk_proof_verify(
    reqs->root,
    reqs->hash,
    msg->nodes,
    &dhash,
    &dhash_len
  );

  if (rc != HSK_SUCCESS) {
    hsk_peer_log(peer, "invalid proof: %d\n", rc);
    return rc;
  }

  if (dhash_len == 0) {
    hsk_map_del(&pool->resolutions, msg->name_hash);

    hsk_name_req_t *c, *n;

    for (c = reqs; c; c = n) {
      n = c->next;
      c->callback(c->name, HSK_SUCCESS, NULL, 0, c->arg);
      free(c);
    }

    return HSK_SUCCESS;
  }

  if (dhash_len != 32) {
    free(dhash);
    hsk_peer_log(peer, "proof hash mismatch\n");
    return HSK_EHASHMISMATCH;
  }

  uint8_t expected[32];
  hsk_hash_blake2b(msg->data, msg->data_len, expected);

  if (memcmp(dhash, expected, 32) != 0) {
    free(dhash);
    hsk_peer_log(peer, "proof hash mismatch\n");
    return HSK_EHASHMISMATCH;
  }

  free(dhash);

  hsk_map_del(&pool->resolutions, msg->name_hash);

  hsk_name_req_t *c, *n;

  for (c = reqs; c; c = n) {
    n = c->next;
    c->callback(c->name, HSK_SUCCESS, msg->data, msg->data_len, c->arg);
    free(c);
  }

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
  hsk_peer_t *peer = (hsk_peer_t *)socket->data;
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  free(conn);

  if (status != 0) {
    hsk_peer_log(peer, "failed connecting: %d\n", status);
    hsk_peer_destroy(peer);
    hsk_pool_refill(pool);
    return;
  }

  peer->connected = true;
  hsk_peer_log(peer, "connected\n");

  status = uv_read_start((uv_stream_t *)socket, alloc_buffer, after_read);

  if (status != 0) {
    hsk_peer_log(peer, "failed reading: %d\n", status);
    hsk_peer_destroy(peer);
    hsk_pool_refill(pool);
    return;
  }

  peer->reading = true;
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
    hsk_pool_refill(pool);
    return;
  }
}

static void
alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  hsk_peer_t *peer = (hsk_peer_t *)handle->data;
  buf->base = (char *)peer->read_buffer;
  buf->len = HSK_BUFFER_SIZE;
}

static void
after_read(uv_stream_t *stream, long int nread, const uv_buf_t *buf) {
  hsk_peer_t *peer = (hsk_peer_t *)stream->data;
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  if (nread < 0) {
    hsk_peer_log(peer, "read error: %d\n", nread);
    hsk_peer_destroy(peer);
    // Why is this causing an assertion failure??
    // hsk_pool_refill(pool);
    return;
  }

  hsk_peer_on_read(peer, (uint8_t *)buf->base, (size_t)nread);
}
