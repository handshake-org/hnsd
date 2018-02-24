#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <uv.h>

#include <ldns/ldns.h>
#include "unbound/unbound.h"

#include "bio.h"
#include "map.h"
#include "packets.h"
#include "hsk-hash.h"
#include "hsk-header.h"
#include "hsk-resource.h"
#include "hsk-proof.h"
#include "hsk-error.h"
#include "utils.h"
#include "bn.h"

/*
 * Defs
 */

#define HSK_BUFFER_SIZE 32768
#define HSK_UDP_BUFFER 4096
#define HSK_UDP_PORT 5369
// #define HSK_UDP_PORT 53
#define HSK_MAX_MESSAGE (4 * 1000 * 1000)
#define HSK_POOL_SIZE 8
#define HSK_USER_AGENT "/hskd:0.0.0/"
#define HSK_PROTO_VERSION 1

#define HSK_MAGIC 0x8efa1fbe
#define HSK_PORT 13038

static const uint8_t HSK_LIMIT[32] = {
  0x7f, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define HSK_BITS 0x207fffff

static const uint8_t HSK_CHAINWORK[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};

#define HSK_TARGET_WINDOW 20
#define HSK_TARGET_SPACING (10 * 60 / 4)
#define HSK_TARGET_TIMESPAN (HSK_TARGET_WINDOW * HSK_TARGET_SPACING)
#define HSK_MIN_ACTUAL ((HSK_TARGET_TIMESPAN * (100 - 16)) / 100)
#define HSK_MAX_ACTUAL ((HSK_TARGET_TIMESPAN * (100 + 32)) / 100)
#define HSK_TARGET_RESET true
#define HSK_NO_RETARGETTING false
#define HSK_CUCKOO_BITS 16
#define HSK_CUCKOO_SIZE 18
#define HSK_CUCKOO_EASE 50

static const uint8_t ZERO_HASH[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const char *genesis_hex = "" // 50 cols
  "0000000000000000000000000000000000000000000000000"
  "00000000000000000000000c3256dc16ad7ac7207b8e678f8"
  "51a1185dd9a1bc4fefc85cce9740ae093da52421717349c29"
  "4000324461cb0eb0527c543909ff0b2c9bd09f59cdfedc090"
  "950003170a2e7597b7b7e3d84c05391d139a62b157e78786d"
  "8c082f29dcf4c111314797d495a00000000ffff7f20000000"
  "0000000000000000000000000012000000000000000000000"
  "0000000000000000000000000000000000000000000000000"
  "0000000000000000000000000000000000000000000000000"
  "0000000000000000000000000";

/*
 * Types
 */

// NOTE: Meant to be HEAP ALLOCATED.
typedef struct hsk_peer {
  void *pool;
  uv_loop_t *loop;
  uv_tcp_t *socket;
  uint64_t id;
  const char *ip;
  int port;
  bool connected;
  bool reading;
  uint8_t rb[HSK_BUFFER_SIZE];
  struct hsk_peer *next;

  bool msg_hdr;
  uint8_t *msg;
  size_t pos;
  size_t waiting;
  char msg_cmd[12];
  uint8_t msg_sum[4];

  // hash_set_t *resolutions;
} hsk_peer_t;

typedef struct {
  uv_loop_t *loop;
  uint64_t peer_id;
  hsk_peer_t *head;
  hsk_peer_t *tail;
  int size;
  hash_map_t *hashes;
  int_map_t *heights;
  hash_map_t *orphans;
  hash_map_t *prevs;
  int64_t height;
  hsk_header_t *tip;
  uv_udp_t *udp;
  uint8_t ub[HSK_UDP_BUFFER];
  hash_map_t *resolutions;
  uv_udp_t *udp2;
  uint8_t ub2[HSK_UDP_BUFFER];
  struct ub_ctx *ub_ctx;
} hsk_pool_t;

typedef struct {
  hsk_peer_t *peer;
  void *data;
  bool should_free;
} hsk__write_data_t;

typedef struct {
  hsk_pool_t *pool;
  void *data;
  bool should_free;
} hsk__send_data_t;

typedef void (*hsk_resolve_cb_t)(
  hsk_pool_t *pool,
  char *name,
  int32_t status,
  uint8_t *data,
  size_t data_len,
  void *arg
);

typedef struct hsk__name_req {
  char name[256];
  uint8_t hash[32];
  uint8_t root[32];
  hsk_resolve_cb_t callback;
  void *arg;
  struct hsk__name_req *next;
} hsk__name_req_t;

typedef struct {
  hsk_pool_t *pool;
  ldns_pkt *req;
  struct sockaddr addr;
  char fqdn[256];
} hsk__dns_req_t;

/*
 * Templates
 */

static hsk_peer_t *
peer_alloc(hsk_pool_t *);

static void
peer_free(hsk_peer_t *);

static void
peer_push(hsk_peer_t *);

static void
peer_connect(hsk_peer_t *, const char *, int);

static void
peer_destroy(hsk_peer_t *);

static void
peer_log(hsk_peer_t *, const char *, ...);

static void
write_cb(uv_write_t *, int);

static void
on_connect(uv_connect_t *, int);

static void
alloc_udp(uv_handle_t *handle, size_t size, uv_buf_t *buf);

static void
send_cb(uv_udp_send_t *, int);

static void
recv_cb(
  uv_udp_t *,
  ssize_t,
  const uv_buf_t *,
  const struct sockaddr *,
  unsigned
);

static void
alloc_udp2(uv_handle_t *handle, size_t size, uv_buf_t *buf);

static void
send_cb2(uv_udp_send_t *, int);

static void
recv_cb2(
  uv_udp_t *,
  ssize_t,
  const uv_buf_t *,
  const struct sockaddr *,
  unsigned
);

static bool
peer_parse(hsk_peer_t *, uint8_t *, size_t);

static void
pool_init_udp(hsk_pool_t *);

static void
pool_init_unbound(hsk_pool_t *);

static void
pool_respond_dns(
  hsk_pool_t *,
  char *,
  int32_t,
  uint8_t *,
  size_t,
  void *
);

static void
pool_respond_unbound(
  hsk_pool_t *,
  char *,
  int32_t,
  uint8_t *,
  size_t,
  void *
);

static void
peer_send_getproof(hsk_peer_t *, uint8_t *, uint8_t *);

static void
pool_send_getproof(hsk_pool_t *, uint8_t *, uint8_t *);

static void
pool_send(
  hsk_pool_t *,
  uint8_t *,
  size_t,
  struct sockaddr *,
  bool
);

static void
pool_send2(
  hsk_pool_t *pool,
  uint8_t *data,
  size_t data_len,
  struct sockaddr *addr,
  bool should_free
);

static void
respond_dns2(void *data, int32_t status, struct ub_result *result);

/*
 * Helpers
 */

static int32_t
qsort_cmp(const void *a, const void *b) {
  int64_t x = *((int64_t *)a);
  int64_t y = *((int64_t *)b);

  if (x < y)
    return -1;

  if (x > y)
    return 1;

  return 0;
}

/*
 * Pool
 */

static void
pool_init(hsk_pool_t *pool, uv_loop_t *loop) {
  if (pool == NULL)
    return;

  pool->loop = loop;
  pool->peer_id = 0;
  pool->head = NULL;
  pool->tail = NULL;
  pool->size = 0;

  pool->hashes = hash_map_alloc();
  pool->heights = int_map_alloc();
  pool->orphans = hash_map_alloc();
  pool->prevs = hash_map_alloc();

  pool->height = 0;
  pool->tip = NULL;
  pool->udp = NULL;

  pool->resolutions = hash_map_alloc();
  pool->udp2 = NULL;
  pool->ub_ctx = NULL;

  size_t size = hex_decode_size((char *)genesis_hex);
  uint8_t raw[size];
  assert(hex_decode((char *)genesis_hex, raw));

  hsk_header_t *tip = xmalloc(sizeof(hsk_header_t));

  tip->cache = false;
  tip->next = NULL;
  tip->height = 0;

  assert(hsk_decode_header(raw, size, tip));

  assert(hsk_get_work((uint8_t *)ZERO_HASH, tip->bits, tip->work));
  hash_map_set(pool->hashes, hsk_cache_header(tip), (void *)tip);
  int_map_set(pool->heights, tip->height, (void *)tip);

  pool->height = tip->height;
  pool->tip = tip;

  pool_init_udp(pool);
  pool_init_unbound(pool);
}

static void
pool_init_udp(hsk_pool_t *pool) {
  uv_loop_t *loop = pool->loop;

  pool->udp = xmalloc(sizeof(uv_udp_t));
  pool->udp->data = (void *)pool;

  uv_udp_init(loop, pool->udp);

  int32_t value = HSK_UDP_BUFFER;
  uv_send_buffer_size((uv_handle_t *)pool->udp, &value);
  uv_recv_buffer_size((uv_handle_t *)pool->udp, &value);

  struct sockaddr_in addr;

  uv_ip4_addr("127.0.0.1", HSK_UDP_PORT, &addr);
  uv_udp_bind(pool->udp, (struct sockaddr *)&addr, 0);

  uv_udp_recv_start(pool->udp, alloc_udp, recv_cb);
}

static const char root_hints[] = ""
  ". 518400 IN NS .\n"
  ". 518400 IN A 127.0.0.1\n";

static const char root_data[] = ""
  ". NS .\n"
  ". A 127.0.0.1\n";

static const char trust_anchors[] = ""
  ". 3600 IN DS 40564 8 2 BAF3CB9FC976E2CDCB49DD9E34BAA2B4C5E8EE7B1574E24ABABD9911C24FF412\n";

static const char trust_anchor[] = ""
  ". DS 40564 8 2 BAF3CB9FC976E2CDCB49DD9E34BAA2B4C5E8EE7B1574E24ABABD9911C24FF412";

void
poll_cb(uv_poll_t *handle, int status, int events) {
  hsk_pool_t *pool = (hsk_pool_t *)handle->data;

  if (status == 0 && (events & UV_READABLE))
    ub_process(pool->ub_ctx);
}

static void
pool_init_unbound(hsk_pool_t *pool) {
  uv_loop_t *loop = pool->loop;

  pool->ub_ctx = ub_ctx_create();
  assert(pool->ub_ctx != NULL);

  assert(ub_ctx_async(pool->ub_ctx, 1) == 0);

  assert(ub_ctx_set_option(pool->ub_ctx, "do-tcp:", "no") == 0);
  assert(ub_ctx_set_option(pool->ub_ctx, "logfile:", "") == 0);
  assert(ub_ctx_set_option(pool->ub_ctx, "use-syslog:", "no") == 0);
  assert(ub_ctx_set_option(pool->ub_ctx, "domain-insecure:", ".") == 0);
  // assert(ub_ctx_set_option(pool->ub_ctx, "root-hints:", "/home/chjj/root.hints") == 0);
  assert(ub_ctx_set_option(pool->ub_ctx, "root-hints:", "") == 0);
  assert(ub_ctx_set_option(pool->ub_ctx, "harden-dnssec-stripped:", "yes") == 0); // default
  assert(ub_ctx_set_option(pool->ub_ctx, "harden-below-nxdomain:", "no") == 0); // default
  assert(ub_ctx_set_option(pool->ub_ctx, "qname-minimisation:", "no") == 0); // default
  assert(ub_ctx_set_option(pool->ub_ctx, "do-not-query-localhost:", "no") == 0);
  assert(ub_ctx_set_option(pool->ub_ctx, "minimal-responses:", "no") == 0); // default
  // assert(ub_ctx_set_option(pool->ub_ctx, "trust-anchor-file:", "filename") == 0);
  assert(ub_ctx_set_option(pool->ub_ctx, "trust-anchor-signaling:", "yes") == 0); // default

  assert(ub_ctx_set_stub(pool->ub_ctx, ".", "127.0.0.1@5369", 0) == 0);
  // assert(ub_ctx_add_ta(pool->ub_ctx, trust_anchor) == 0);
  // assert(ub_ctx_zone_remove(pool->ub_ctx, ".") == 0);
  // assert(ub_ctx_data_remove(pool->ub_ctx, ".") == 0);
  assert(ub_ctx_zone_add(pool->ub_ctx, ".", "nodefault") == 0);
  // assert(ub_ctx_data_add(pool->ub_ctx, ". NS .") == 0);
  // assert(ub_ctx_data_add(pool->ub_ctx, ". A 127.0.0.1") == 0);

  pool->udp2 = xmalloc(sizeof(uv_udp_t));
  pool->udp2->data = (void *)pool;

  uv_udp_init(loop, pool->udp2);

  uv_poll_t *poll = xmalloc(sizeof(uv_poll_t));
  poll->data = (void *)pool;
  uv_poll_init(pool->loop, poll, ub_fd(pool->ub_ctx));
  uv_poll_start(poll, UV_READABLE, poll_cb);

  int32_t value = HSK_UDP_BUFFER;
  uv_send_buffer_size((uv_handle_t *)pool->udp2, &value);
  uv_recv_buffer_size((uv_handle_t *)pool->udp2, &value);

  struct sockaddr_in addr;

  uv_ip4_addr("127.0.0.1", HSK_UDP_PORT + 1, &addr);
  uv_udp_bind(pool->udp2, (struct sockaddr *)&addr, 0);

  uv_udp_recv_start(pool->udp2, alloc_udp2, recv_cb2);
}

static hsk_pool_t *
pool_alloc(uv_loop_t *loop) {
  hsk_pool_t *pool = xmalloc(sizeof(hsk_pool_t));
  pool_init(pool, loop);
  return pool;
}

static void
pool_free(hsk_pool_t *pool) {
  if (pool == NULL)
    return;

  hsk_peer_t *c, *n;

  for (c = pool->head; c; c = n) {
    n = c->next;
    peer_free(c);
  }

  free(pool);
}

static void
pool_destroy(hsk_pool_t *pool) {
  if (pool == NULL)
    return;

  hsk_peer_t *c, *n;

  for (c = pool->head; c; c = n) {
    n = c->next;
    peer_destroy(c);
  }

  free(pool);
}

static void
pool_getaddr(hsk_pool_t *pool, const char **ip, int *port) {
  *ip = "127.0.0.1";
  *port = HSK_PORT;
}

static void
pool_refill(hsk_pool_t *pool) {
  while (pool->size < HSK_POOL_SIZE) {
    hsk_peer_t *peer = peer_alloc(pool);
    peer_push(peer);

    const char *ip;
    int port;
    pool_getaddr(pool, &ip, &port);

    peer_connect(peer, ip, port);
  }
}

static void
pool_send_getproof(hsk_pool_t *pool, uint8_t *name_hash, uint8_t *root) {
  hsk_peer_t *peer = pool->head;

  if (!peer)
    return;

  peer_send_getproof(peer, name_hash, root);
}

static void
pool_resolve(
  hsk_pool_t *pool,
  char *name,
  hsk_resolve_cb_t callback,
  void *arg
) {
  uint8_t *root = pool->tip->trie_root;
  hsk__name_req_t *r = xmalloc(sizeof(hsk__name_req_t));

  strcpy(r->name, name);

  hsk_blake2b(name, strlen(name), r->hash);

  memcpy(r->root, root, 32);

  r->callback = callback;
  r->arg = arg;
  r->next = NULL;

  hsk__name_req_t *nr = hash_map_get(pool->resolutions, r->hash);

  if (nr)
    r->next = nr;

  hash_map_set(pool->resolutions, r->hash, (void *)r);

  pool_send_getproof(pool, r->hash, root);
}

static void
pool_on_recv(
  hsk_pool_t *pool,
  uint8_t *data,
  size_t data_len,
  struct sockaddr *addr,
  uint32_t flags
) {
  ldns_pkt *req;
  ldns_status rc = ldns_wire2pkt(&req, data, data_len);

  if (rc != LDNS_STATUS_OK) {
    printf("bad dns message: %s\n", ldns_get_errorstr_by_id(rc));
    return;
  }

  ldns_pkt_opcode opcode = ldns_pkt_get_opcode(req);
  ldns_pkt_rcode rcode = ldns_pkt_get_rcode(req);
  ldns_rr_list *qd = ldns_pkt_question(req);
  ldns_rr_list *an = ldns_pkt_answer(req);
  ldns_rr_list *ns = ldns_pkt_authority(req);

  if (opcode != LDNS_PACKET_QUERY
      || rcode != LDNS_RCODE_NOERROR
      || ldns_rr_list_rr_count(qd) != 1
      || ldns_rr_list_rr_count(an) != 0
      || ldns_rr_list_rr_count(ns) != 0) {
    ldns_pkt_free(req);
    return;
  }

  // Grab the first question.
  ldns_rr *qs = ldns_rr_list_rr(qd, 0);

  printf("received dns query:\n");
  ldns_rr_print(stdout, qs);

  uint16_t id = ldns_pkt_id(req);
  const ldns_rdf *rdf = ldns_rr_owner(qs);
  const ldns_rr_type type = ldns_rr_get_type(qs);
  const ldns_rr_class class = ldns_rr_get_class(qs);

  if (class != LDNS_RR_CLASS_IN) {
    ldns_pkt_free(req);
    return;
  }

  char *fqdn = ldns_rdf2str(rdf);
  assert(fqdn != NULL);
  size_t size = strlen(fqdn);

  if (size == 0 || size > 255 || fqdn[size - 1] != '.') {
    free(fqdn);
    ldns_pkt_free(req);
    return;
  }

  // Authoritative.
  if (size == 1) {
    free(fqdn);
    ldns_pkt_free(req);

    bool edns = ldns_pkt_edns_udp_size(req) == 4096;
    bool dnssec = ldns_pkt_edns_do(req);

    uint8_t *wire;
    size_t wire_len;

    if (!hsk_resource_root(id, type, edns, dnssec, &wire, &wire_len))
      return;

    pool_send(pool, wire, wire_len, addr, true);

    return;
  }

  int32_t i = size - 2;

  for (; i >= 0; i--) {
    if (fqdn[i] == '.')
      break;
  }

  i += 1;
  size_t nsize = (size - 1) - i;
  char name[256];
  memcpy(name, fqdn + i, nsize);
  name[nsize] = '\0';

  hsk__dns_req_t *dr = xmalloc(sizeof(hsk__dns_req_t));
  dr->pool = pool;
  dr->req = req;
  memcpy((void *)&dr->addr, (void *)addr, sizeof(struct sockaddr));
  memcpy(dr->fqdn, fqdn, size + 1);
  free(fqdn);

  pool_resolve(pool, name, pool_respond_dns, (void *)dr);
}

static void
pool_respond_dns(
  hsk_pool_t *pool,
  char *name,
  int32_t status,
  uint8_t *data,
  size_t data_len,
  void *arg
) {
  hsk__dns_req_t *dr = (hsk__dns_req_t *)arg;
  ldns_pkt *req = dr->req;
  struct sockaddr *addr = &dr->addr;
  char *fqdn = dr->fqdn;

  if (status != HSK_SUCCESS) {
    ldns_pkt_free(req);
    free(dr);
    return;
  }

  uint8_t *wire;
  size_t wire_len;

  ldns_rr *qs = ldns_rr_list_rr(ldns_pkt_question(req), 0);

  bool edns = ldns_pkt_edns_udp_size(req) == 4096;
  bool dnssec = ldns_pkt_edns_do(req);
  uint16_t id = ldns_pkt_id(req);
  uint16_t type = (uint16_t)ldns_rr_get_type(qs);

  ldns_pkt_free(req);

  // Doesn't exist.
  if (data == NULL) {
    if (!hsk_resource_to_nx(id, fqdn, type, edns, dnssec, &wire, &wire_len)) {
      free(dr);
      return;
    }
    pool_send(pool, wire, wire_len, addr, true);
    free(dr);
    return;
  }

  hsk_resource_t *rs;

  if (!hsk_decode_resource(data, data_len, &rs)) {
    ldns_pkt_free(req);
    free(dr);
    return;
  }

  if (!hsk_resource_to_dns(rs, id, fqdn, type, edns, dnssec, &wire, &wire_len)) {
    hsk_free_resource(rs);
    free(dr);
    return;
  }

  hsk_free_resource(rs);

  pool_send(pool, wire, wire_len, addr, true);

  free(dr);
}

static void
pool_send(
  hsk_pool_t *pool,
  uint8_t *data,
  size_t data_len,
  struct sockaddr *addr,
  bool should_free
) {
  hsk__send_data_t *sd = (hsk__send_data_t *)xmalloc(sizeof(hsk__send_data_t));
  sd->pool = pool;
  sd->data = (void *)data;
  sd->should_free = should_free;

  uv_udp_send_t *req = (uv_udp_send_t *)xmalloc(sizeof(uv_udp_send_t));
  req->data = (void *)sd;

  uv_buf_t bufs[] = {
    { .base = data, .len = data_len }
  };

  int status = uv_udp_send(req, pool->udp, bufs, 1, addr, send_cb);

  if (status != 0) {
    free(sd);
    free(req);
    if (should_free)
      free(data);
    printf("failed sending: %d\n", status);
    return;
  }
}

static void
pool_on_recv2(
  hsk_pool_t *pool,
  uint8_t *data,
  size_t data_len,
  struct sockaddr *addr,
  uint32_t flags
) {
  ldns_pkt *req;
  ldns_status rc = ldns_wire2pkt(&req, data, data_len);

  if (rc != LDNS_STATUS_OK) {
    printf("bad dns message: %s\n", ldns_get_errorstr_by_id(rc));
    return;
  }

  ldns_pkt_opcode opcode = ldns_pkt_get_opcode(req);
  ldns_pkt_rcode rcode = ldns_pkt_get_rcode(req);
  ldns_rr_list *qd = ldns_pkt_question(req);
  ldns_rr_list *an = ldns_pkt_answer(req);
  ldns_rr_list *ns = ldns_pkt_authority(req);

  if (opcode != LDNS_PACKET_QUERY
      || rcode != LDNS_RCODE_NOERROR
      || ldns_rr_list_rr_count(qd) != 1
      || ldns_rr_list_rr_count(an) != 0
      || ldns_rr_list_rr_count(ns) != 0) {
    ldns_pkt_free(req);
    return;
  }

  // Grab the first question.
  ldns_rr *qs = ldns_rr_list_rr(qd, 0);

  printf("received recursive dns query:\n");
  ldns_rr_print(stdout, qs);

  uint16_t id = ldns_pkt_id(req);
  bool edns = ldns_pkt_edns_udp_size(req) == 4096;
  bool dnssec = ldns_pkt_edns_do(req);
  const ldns_rdf *rdf = ldns_rr_owner(qs);
  const ldns_rr_type rrtype = ldns_rr_get_type(qs);
  const ldns_rr_class rrclass = ldns_rr_get_class(qs);

  if (rrclass != LDNS_RR_CLASS_IN) {
    ldns_pkt_free(req);
    return;
  }

  char *name = ldns_rdf2str(rdf);
  assert(name != NULL);
  uint16_t type = (uint16_t)rrtype;
  uint16_t class = (uint16_t)rrclass;

  hsk__dns_req_t *dr = xmalloc(sizeof(hsk__dns_req_t));
  dr->pool = pool;
  dr->req = req;
  memcpy((void *)&dr->addr, (void *)addr, sizeof(struct sockaddr));
  strcpy(dr->fqdn, name);
  free(name);

  int32_t r = ub_resolve_async(
    pool->ub_ctx,
    dr->fqdn,
    type,
    class,
    (void *)dr,
    respond_dns2,
    NULL
  );

  if (r != 0) {
    printf("resolve error: %s\n", ub_strerror(r));
    return;
  }
}

static void
pool_respond_dns2(
  hsk_pool_t *pool,
  ldns_pkt *req,
  int32_t status,
  struct ub_result *result,
  struct sockaddr *addr
) {
  if (status != 0) {
    printf("resolve error: %s\n", ub_strerror(status));
    return;
  }

  uint16_t id = ldns_pkt_id(req);
  bool edns = ldns_pkt_edns_udp_size(req) == 4096;
  bool dnssec = ldns_pkt_edns_do(req);

  // result->havedata
  // result->nxdomain
  // result->secure
  // result->bogus

  ldns_pkt *res;
  ldns_status rc = ldns_wire2pkt(&res, result->answer_packet, result->answer_len);

  if (rc != LDNS_STATUS_OK) {
    printf("bad dns message: %s\n", ldns_get_errorstr_by_id(rc));
    return;
  }

  ldns_pkt_set_id(res, id);

  if (edns) {
    ldns_pkt_set_edns_udp_size(res, 4096);
    if (dnssec) {
      ldns_pkt_set_edns_do(res, 1);
      if (result->secure && !result->bogus)
        ldns_pkt_set_ad(res, 1);
      else
        ldns_pkt_set_ad(res, 0);
    }
  }

  uint8_t *wire;
  size_t wire_len;

  ldns_status r = ldns_pkt2wire(&wire, res, &wire_len);

  ldns_pkt_free(res);

  // ldns_pkt_print();
  if (r == LDNS_STATUS_OK)
    pool_send2(pool, wire, wire_len, addr, true);

  // if (result->havedata) {
  //   printf("The address is %s\n",
  //     inet_ntoa(*(struct in_addr*)result->data[0]));
  // }
}

static void
pool_send2(
  hsk_pool_t *pool,
  uint8_t *data,
  size_t data_len,
  struct sockaddr *addr,
  bool should_free
) {
  hsk__send_data_t *sd = (hsk__send_data_t *)xmalloc(sizeof(hsk__send_data_t));
  sd->pool = pool;
  sd->data = (void *)data;
  sd->should_free = should_free;

  uv_udp_send_t *req = (uv_udp_send_t *)xmalloc(sizeof(uv_udp_send_t));
  req->data = (void *)sd;

  uv_buf_t bufs[] = {
    { .base = data, .len = data_len }
  };

  int status = uv_udp_send(req, pool->udp2, bufs, 1, addr, send_cb2);

  if (status != 0) {
    free(sd);
    free(req);
    if (should_free)
      free(data);
    printf("failed sending: %d\n", status);
    return;
  }
}

/*
 * Blockchain
 */

static void
pool_get_locator(hsk_pool_t *pool, hsk_getheaders_msg_t *msg) {
  int32_t i = 0;
  hsk_header_t *tip = pool->tip;
  int64_t height = pool->height;
  int64_t step = 1;

  hsk_hash_header(tip, msg->hashes[i++]);

  while (height > 0) {
    height -= step;

    if (height < 0)
      height = 0;

    if (i > 10)
      step *= 2;

    if (i == sizeof(msg->hashes) - 1)
      height = 0;

    hsk_header_t *hdr =
      (hsk_header_t *)int_map_get(pool->heights, height);

    assert(hdr);

    hsk_hash_header(hdr, msg->hashes[i++]);
  }

  msg->hash_count = i;
}

static int64_t
pool_get_mtp(hsk_pool_t *pool, hsk_header_t *hdr) {
  int32_t timespan = 11;
  int64_t median[11];
  size_t size = 0;
  int32_t i;

  for (i = 0; i < timespan && hdr; i++) {
    median[i] = (int64_t)hdr->time;
    hdr = (hsk_header_t *)hash_map_get(pool->hashes, hdr->prev_block);
    size += 1;
  }

  qsort((void *)median, size, sizeof(int64_t), qsort_cmp);

  return median[size >> 1];
}

static uint32_t
pool_retarget(hsk_pool_t *pool, hsk_header_t *prev) {
  uint32_t bits = HSK_BITS;
  uint8_t *limit = (uint8_t *)HSK_LIMIT;
  int32_t window = HSK_TARGET_WINDOW;
  int32_t timespan = HSK_TARGET_TIMESPAN;
  int32_t min = HSK_MIN_ACTUAL;
  int32_t max = HSK_MAX_ACTUAL;

  bn_t target_bn;
  bignum_init(&target_bn);

  hsk_header_t *last = prev;
  hsk_header_t *first = last;
  int32_t i;

  for (i = 0; first && i < window; i++) {
    uint8_t diff[32];
    assert(hsk_to_target(first->bits, diff));
    bn_t diff_bn;
    bignum_from_array(&diff_bn, diff, 32);
    bignum_add(&target_bn, &diff_bn, &target_bn);
    first = (hsk_header_t *)hash_map_get(pool->hashes, first->prev_block);
  }

  if (!first)
    return bits;

  bn_t window_bn;
  bignum_from_int(&window_bn, window);

  bignum_div(&target_bn, &window_bn, &target_bn);

  int64_t start = pool_get_mtp(pool, first);
  int64_t end = pool_get_mtp(pool, last);
  int64_t diff = end - start;
  int64_t actual = timespan + ((diff - timespan) / 4);

  assert(actual >= 0);

  if (actual < min)
    actual = min;

  if (actual > max)
    actual = max;

  bn_t actual_bn;
  bignum_from_int(&actual_bn, actual);

  bn_t timespan_bn;
  bignum_from_int(&timespan_bn, timespan);

  bignum_mul(&target_bn, &actual_bn, &target_bn);
  bignum_div(&target_bn, &timespan_bn, &target_bn);

  bn_t limit_bn;
  bignum_from_array(&limit_bn, limit, 32);

  if (bignum_cmp(&target_bn, &limit_bn) > 0)
    return bits;

  uint8_t target[32];
  bignum_to_array(&target_bn, target, 32);

  uint32_t cmpct;

  assert(hsk_to_bits(target, &cmpct));

  return cmpct;
}

static uint32_t
pool_get_target(hsk_pool_t *pool, int64_t time, hsk_header_t *prev) {
  // Genesis
  if (!prev) {
    // assert(time === GENESIS_TIME);
    return HSK_BITS;
  }

  if (HSK_NO_RETARGETTING)
    return HSK_BITS;

  if (HSK_TARGET_RESET) {
    // Special behavior for testnet:
    if (time > (int64_t)prev->time + HSK_TARGET_SPACING * 2)
      return HSK_BITS;
   }

  return pool_retarget(pool, prev);
}

static hsk_header_t *
pool_find_fork(hsk_pool_t *pool, hsk_header_t *fork, hsk_header_t *longer) {
  while (!hsk_header_equal(fork, longer)) {
    while (longer->height > fork->height) {
      longer = hash_map_get(pool->hashes, longer->prev_block);
      if (!longer)
        return NULL;
    }

    if (hsk_header_equal(fork, longer))
      return fork;

    fork = hash_map_get(pool->hashes, fork->prev_block);

    if (!fork)
      return NULL;
  }

  return fork;
}

static void
pool_reorganize(hsk_pool_t *pool, hsk_header_t *competitor) {
  hsk_header_t *tip = pool->tip;
  hsk_header_t *fork = pool_find_fork(pool, tip, competitor);

  assert(fork);

  // Blocks to disconnect.
  hsk_header_t *disconnect = NULL;
  hsk_header_t *entry = tip;
  hsk_header_t *tail = NULL;
  while (!hsk_header_equal(entry, fork)) {
    assert(!entry->next);

    if (!disconnect)
      disconnect = entry;

    if (tail)
      tail->next = entry;

    tail = entry;

    entry = hash_map_get(pool->hashes, entry->prev_block);
    assert(entry);
  }

  // Blocks to connect.
  entry = competitor;
  hsk_header_t *connect = NULL;
  while (!hsk_header_equal(entry, fork)) {
    assert(!entry->next);

    if (connect)
      entry->next = connect;

    connect = entry;

    entry = hash_map_get(pool->hashes, entry->prev_block);
    assert(entry);
  }

  // Disconnect blocks.
  hsk_header_t *c, *n;
  for (c = disconnect; c; c = n) {
    n = c->next;
    c->next = NULL;
    int_map_del(pool->heights, c->height);
  }

  // Connect blocks (backwards, save last).
  for (c = connect; c; c = n) {
    n = c->next;
    c->next = NULL;

    if (!n) // halt on last
      break;

    int_map_set(pool->heights, c->height, (void *)c);
  }
}

static int32_t
pool_add_block(hsk_pool_t *pool, hsk_header_t *h, hsk_peer_t *peer) {
  hsk_header_t *hdr = xmalloc(sizeof(hsk_header_t));
  memcpy((void *)hdr, (void *)h, sizeof(hsk_header_t));
  hdr->next = NULL;

  uint8_t *hash = hsk_cache_header(hdr);

  peer_log(peer, "adding block: %s\n", hex_encode32(hash));

  if (hdr->time > now() + 2 * 60 * 60) {
    peer_log(peer, "  rejected: time-too-new\n");
    return HSK_EFAILURE;
  }

  if (hash_map_has(pool->hashes, hash)) {
    peer_log(peer, "  rejected: duplicate\n");
    return HSK_EFAILURE;
  }

  if (hash_map_has(pool->orphans, hash)) {
    peer_log(peer, "  rejected: duplicate-orphan\n");
    return HSK_EFAILURE;
  }

  int32_t rc = hsk_verify_pow(hdr);

  if (rc != HSK_SUCCESS) {
    peer_log(peer, "  rejected: cuckoo error %d\n", rc);
    return rc;
  }

  hsk_header_t *prev =
    (hsk_header_t *)hash_map_get(pool->hashes, hdr->prev_block);

  if (prev == NULL) {
    peer_log(peer, "  stored as orphan\n");
    hash_map_set(pool->orphans, hash, (void *)hdr);
    hash_map_set(pool->prevs, hdr->prev_block, (void *)hdr);
    return HSK_EFAILURE;
  }

  int64_t mtp = pool_get_mtp(pool, prev);

  if ((int64_t)hdr->time <= mtp) {
    peer_log(peer, "  rejected: time-too-old\n");
    return HSK_EFAILURE;
  }

  uint32_t bits = pool_get_target(pool, hdr->time, prev);

  if (hdr->bits != bits) {
    peer_log(peer, "  rejected: bad-diffbits\n");
    return HSK_EFAILURE;
  }

  hdr->height = prev->height + 1;

  assert(hsk_get_work(prev->work, hdr->bits, hdr->work));

  if (memcmp(hdr->work, pool->tip->work, 32) <= 0) {
    hash_map_set(pool->hashes, hash, (void *)hdr);
    peer_log(peer, "  stored on alternate chain\n");
  } else {
    if (memcmp(hdr->prev_block, hsk_cache_header(pool->tip), 32) != 0) {
      peer_log(peer, "  reorganizing...\n");
      pool_reorganize(pool, hdr);
    }

    hash_map_set(pool->hashes, hash, (void *)hdr);
    int_map_set(pool->heights, hdr->height, (void *)hdr);

    pool->height = hdr->height;
    pool->tip = hdr;

    peer_log(peer, "  added to main chain\n");
    peer_log(peer, "  new height: %d\n", pool->height);
  }

  return HSK_SUCCESS;
}

/*
 * Peer
 */

static void
peer_init(hsk_peer_t *peer, hsk_pool_t *pool) {
  if (peer == NULL)
    return;

  assert(pool != NULL);
  assert(pool->loop != NULL);

  peer->pool = (void *)pool;
  peer->loop = pool->loop;
  peer->socket = NULL;
  peer->id = pool->peer_id++;
  peer->connected = false;
  peer->reading = false;
  peer->next = NULL;

  peer->msg_hdr = false;
  peer->msg = xmalloc(24);
  peer->pos = 0;
  peer->waiting = 24;
  memset(peer->msg_cmd, 0, sizeof peer->msg_cmd);
  memset(peer->msg_sum, 0, sizeof peer->msg_sum);
}

static hsk_peer_t *
peer_alloc(hsk_pool_t *pool) {
  hsk_peer_t *peer = xmalloc(sizeof(hsk_peer_t));
  peer_init(peer, pool);
  return peer;
}

static void
peer_free(hsk_peer_t *peer) {
  if (peer == NULL)
    return;

  if (peer->socket) {
    free(peer->socket);
    peer->socket = NULL;
  }

  free(peer);
}

static void
peer_push(hsk_peer_t *peer) {
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  if (peer == NULL)
    return;

  peer->next = NULL;

  if (pool->head == NULL)
    pool->head = peer;

  if (pool->tail)
    pool->tail->next = peer;

  pool->tail = peer;
  pool->size += 1;
}

static void
peer_remove(hsk_peer_t *peer) {
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  if (peer == NULL)
    return;

  if (pool->head == NULL)
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

  if (prev == NULL)
    return;

  if (pool->tail == peer)
    pool->tail = prev;

  prev->next = peer->next;

  pool->size -= 1;
}

static void
peer_connect(hsk_peer_t *peer, const char *ip, int port) {
  assert(peer->pool && peer->loop && !peer->connected && !peer->socket);

  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;
  uv_loop_t *loop = pool->loop;

  // Socket is uv_stream_t, also a uv_handle_t -- ends up on conn->handle.
  uv_tcp_t *socket = (uv_tcp_t *)xmalloc(sizeof(uv_tcp_t));
  uv_tcp_init(loop, socket);

  // Conn is uv_req_t, contains socket.
  uv_connect_t *conn = (uv_connect_t *)xmalloc(sizeof(uv_connect_t));

  // Make the peer reference the handle,
  // and the handle reference the peer.
  socket->data = (void *)peer;
  peer->socket = socket;
  peer->ip = ip;
  peer->port = port;

  struct sockaddr_in dest;
  uv_ip4_addr(ip, port, &dest);
  uv_tcp_connect(conn, socket, (const struct sockaddr *)&dest, on_connect);
}

static void
peer_destroy(hsk_peer_t *peer) {
  if (peer->reading) {
    assert(peer->socket);
    uv_read_stop((uv_stream_t *)peer->socket);
    peer->reading = false;
  }

  if (peer->connected) {
    assert(peer->socket);
    uv_close((uv_handle_t *)peer->socket, NULL);
    peer->connected = false;
  }

  peer_remove(peer);
  peer_free(peer);
}

static void
peer_log(hsk_peer_t *peer, const char *fmt, ...) {
  printf("peer %d (%s,%d): ", peer->id, peer->ip, peer->port);

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

static void
peer_write(hsk_peer_t *peer, uint8_t *data, size_t data_len, bool should_free) {
  hsk__write_data_t *wd = (hsk__write_data_t *)xmalloc(sizeof(hsk__write_data_t));
  wd->peer = peer;
  wd->data = (void *)data;
  wd->should_free = should_free;

  uv_write_t *req = (uv_write_t *)xmalloc(sizeof(uv_write_t));
  req->data = (void *)wd;

  uv_stream_t *stream = (uv_stream_t *)peer->socket;

  uv_buf_t bufs[] = {
    { .base = data, .len = data_len }
  };

  int status = uv_write(req, stream, bufs, 1, write_cb);

  if (status != 0) {
    free(wd);
    free(req);
    if (should_free)
      free(data);
    hsk_pool_t *pool = (hsk_pool_t *)peer->pool;
    peer_log(peer, "failed writing: %d\n", status);
    peer_destroy(peer);
    pool_refill(pool);
    return;
  }
}

static void
peer_send(hsk_peer_t *peer, hsk_msg_t *msg) {
  int32_t msg_size = hsk_msg_size(msg);
  assert(msg_size != -1);

  size_t size = 24 + msg_size;
  uint8_t *data = xmalloc(size);

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
  hsk_hash256(data + 24, size - 24, hash);
  memcpy(data + 20, hash, 4);

  peer_write(peer, data, size, true);
}

static void
peer_on_read(hsk_peer_t *peer, uint8_t *data, size_t data_len) {
  while (data_len >= peer->waiting) {
    memcpy(peer->msg + peer->pos, data, peer->waiting);
    peer->pos += peer->waiting;

    data += peer->waiting;
    data_len -= peer->waiting;

    peer_parse(peer, peer->msg, peer->pos);
  }

  memcpy(peer->msg + peer->pos, data, data_len);
  peer->pos += data_len;
}

static void
peer_send_version(hsk_peer_t *peer, hsk_version_msg_t *theirs) {
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  hsk_version_msg_t msg = { .cmd = MSG_VERSION };
  hsk_msg_init((hsk_msg_t *)&msg);

  msg.version = HSK_PROTO_VERSION;
  msg.services = 0;
  msg.time = now();

  if (theirs) {
    msg.remote.time = theirs->time;
    msg.remote.services = theirs->services;
  }

  msg.remote.type = 0;
  // memcpy(msg.remote.addr, x, 36); // set to their addr
  msg.remote.port = peer->port;
  msg.nonce = 0;
  strcpy(msg.agent, HSK_USER_AGENT);
  msg.height = pool->height;

  peer_send(peer, (hsk_msg_t *)&msg);
}

static void
peer_send_verack(hsk_peer_t *peer) {
  hsk_version_msg_t msg = { .cmd = MSG_VERACK };
  peer_send(peer, (hsk_msg_t *)&msg);
}

static void
peer_send_ping(hsk_peer_t *peer, uint64_t nonce) {
  hsk_ping_msg_t msg = {
    .cmd = MSG_PING,
    .nonce = nonce
  };
  peer_send(peer, (hsk_msg_t *)&msg);
}

static void
peer_send_pong(hsk_peer_t *peer, uint64_t nonce) {
  hsk_pong_msg_t msg = {
    .cmd = MSG_PONG,
    .nonce = nonce
  };
  peer_send(peer, (hsk_msg_t *)&msg);
}

static void
peer_send_sendheaders(hsk_peer_t *peer) {
  hsk_version_msg_t msg = { .cmd = MSG_SENDHEADERS };
  peer_send(peer, (hsk_msg_t *)&msg);
}

static void
peer_send_getheaders(hsk_peer_t *peer, uint8_t *stop) {
  hsk_getheaders_msg_t msg = { .cmd = MSG_GETHEADERS };

  hsk_msg_init((hsk_msg_t *)&msg);

  pool_get_locator(peer->pool, &msg);

  if (stop)
    memcpy(msg.stop, stop, 32);

  peer_send(peer, (hsk_msg_t *)&msg);
}

static void
peer_send_getproof(hsk_peer_t *peer, uint8_t *name_hash, uint8_t *root) {
  hsk_getproof_msg_t msg = { .cmd = MSG_GETPROOF };
  hsk_msg_init((hsk_msg_t *)&msg);

  memcpy(msg.name_hash, name_hash, 32);
  memcpy(msg.root, root, 32);

  peer_send(peer, (hsk_msg_t *)&msg);
}

static inline void
peer_handle_version(hsk_peer_t *peer, hsk_version_msg_t *msg) {
  peer_send_verack(peer);
  peer_send_version(peer, msg);
}

static inline void
peer_handle_verack(hsk_peer_t *peer, hsk_verack_msg_t *msg) {
  peer_send_sendheaders(peer);
  peer_send_getheaders(peer, NULL);
}

static inline void
peer_handle_ping(hsk_peer_t *peer, hsk_ping_msg_t *msg) {
  peer_send_pong(peer, msg->nonce);
}

static inline void
peer_handle_pong(hsk_peer_t *peer, hsk_pong_msg_t *msg) {
  peer_log(peer, "received pong\n");
}

static inline void
peer_handle_addr(hsk_peer_t *peer, hsk_addr_msg_t *msg) {
  peer_log(peer, "received %d addrs\n", msg->addr_count);
  // int32_t i;
  // for (i = 0; i < m->addr_count; i++)
  //   hsk_addr_t *addr = &m->addrs[i];
}

static inline void
peer_handle_headers(hsk_peer_t *peer, hsk_headers_msg_t *msg) {
  peer_log(peer, "received %d headers\n", msg->header_count);

  if (msg->header_count == 0)
    return;

  if (msg->header_count > 2000)
    return;

  uint8_t *last = NULL;
  hsk_header_t *c;

  for (c = msg->headers; c; c = c->next) {
    if (last && memcmp(c->prev_block, last, 32) != 0) {
      peer_log(peer, "invalid header chain\n");
      return;
    }

    last = hsk_cache_header(c);

    int32_t rc = hsk_verify_pow(c);

    if (rc != HSK_SUCCESS) {
      peer_log(peer, "invalid header pow\n");
      return;
    }
  }

  for (c = msg->headers; c; c = c->next) {
    int32_t rc = pool_add_block(peer->pool, c, peer);
    if (rc != HSK_SUCCESS)
      peer_log(peer, "failed adding block: %d\n", rc);
  }

  if (msg->header_count == 2000) {
    peer_log(peer, "requesting more headers\n");
    peer_send_getheaders(peer, NULL);
  }
}

static inline void
peer_handle_proof(hsk_peer_t *peer, hsk_proof_msg_t *msg) {
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  peer_log(peer, "received proof\n");

  if (msg->data_len > 512) {
    peer_log(peer, "invalid proof data\n");
    return;
  }

  hsk__name_req_t *reqs = hash_map_get(pool->resolutions, msg->name_hash);

  if (reqs == NULL) {
    peer_log(peer, "received unsolicited proof\n");
    return;
  }

  if (memcmp(msg->root, reqs->root, 32) != 0) {
    peer_log(peer, "proof hash mismatch\n");
    return;
  }

  uint8_t *dhash;
  size_t dhash_len;

  // TODO: Verify length in function.
  // Have return pointer so dhash can be stack allocated.
  // Add extra arg for bool *exists
  // Make it a consensus rule that 0-length records cannot exist.
  int32_t rc = hsk_verify_proof(
    reqs->root,
    reqs->hash,
    msg->nodes,
    &dhash,
    &dhash_len
  );

  if (rc != HSK_SUCCESS) {
    peer_log(peer, "invalid proof: %d\n", rc);
    return;
  }

  if (dhash_len == 0) {
    hash_map_del(pool->resolutions, msg->name_hash);

    hsk__name_req_t *c, *n;

    for (c = reqs; c; c = n) {
      n = c->next;
      c->callback(pool, c->name, HSK_SUCCESS, NULL, 0, c->arg);
      free(c);
    }

    return;
  }

  if (dhash_len != 32) {
    free(dhash);
    peer_log(peer, "proof hash mismatch\n");
    return;
  }

  uint8_t expected[32];
  hsk_blake2b(msg->data, msg->data_len, expected);

  if (memcmp(dhash, expected, 32) != 0) {
    free(dhash);
    peer_log(peer, "proof hash mismatch\n");
    return;
  }

  free(dhash);

  hash_map_del(pool->resolutions, msg->name_hash);

  hsk__name_req_t *c, *n;

  for (c = reqs; c; c = n) {
    n = c->next;
    c->callback(pool, c->name, HSK_SUCCESS, msg->data, msg->data_len, c->arg);
    free(c);
  }
}

static void
peer_handle_msg(hsk_peer_t *peer, hsk_msg_t *msg) {
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  peer_log(peer, "handling msg: %s\n", hsk_msg_str(msg->cmd));

  switch (msg->cmd) {
    case MSG_VERSION: {
      peer_handle_version(peer, (hsk_version_msg_t *)msg);
      break;
    }
    case MSG_VERACK: {
      peer_handle_verack(peer, (hsk_verack_msg_t *)msg);
      break;
    }
    case MSG_PING: {
      peer_handle_ping(peer, (hsk_ping_msg_t *)msg);
      break;
    }
    case MSG_PONG: {
      peer_handle_pong(peer, (hsk_pong_msg_t *)msg);
      break;
    }
    case MSG_GETADDR: {
      peer_log(peer, "cannot handle getaddr\n");
      break;
    }
    case MSG_ADDR: {
      peer_handle_addr(peer, (hsk_addr_msg_t *)msg);
      break;
    }
    case MSG_GETHEADERS: {
      peer_log(peer, "cannot handle getheaders\n");
      break;
    }
    case MSG_HEADERS: {
      peer_handle_headers(peer, (hsk_headers_msg_t *)msg);
      break;
    }
    case MSG_SENDHEADERS: {
      peer_log(peer, "cannot handle sendheaders\n");
      break;
    }
    case MSG_GETPROOF: {
      peer_log(peer, "cannot handle getproof\n");
      break;
    }
    case MSG_PROOF: {
      peer_handle_proof(peer, (hsk_proof_msg_t *)msg);
      break;
    }
  }
}

static bool
peer_parse_hdr(hsk_peer_t *peer, uint8_t *msg, size_t msg_len) {
  uint32_t magic;

  if (!read_u32(&msg, &msg_len, &magic)) {
    peer_log(peer, "invalid header\n");
    return false;
  }

  if (magic != HSK_MAGIC) {
    peer_log(peer, "invalid magic: %d\n", magic);
    return false;
  }

  int32_t i = 0;
  for (; msg[i] != 0 && i < 12; i++);

  if (i == 12) {
    peer_log(peer, "invalid command\n");
    return false;
  }

  char *cmd = msg;
  size_t cmd_len = i;

  msg += 12;
  msg_len -= 12;

  uint32_t size;

  if (!read_u32(&msg, &msg_len, &size)) {
    peer_log(peer, "invalid header: %s\n", cmd);
    return false;
  }

  if (size > HSK_MAX_MESSAGE) {
    peer_log(peer, "invalid msg size: %s - %d\n", cmd, size);
    return false;
  }

  if (!read_bytes(&msg, &msg_len, peer->msg_sum, 4)) {
    peer_log(peer, "invalid header: %s\n", cmd);
    return false;
  }

  peer->msg_hdr = true;
  memcpy(peer->msg_cmd, cmd, cmd_len + 1);
  peer->msg = xrealloc(peer->msg, size);
  peer->pos = 0;
  peer->waiting = size;

  peer_log(peer, "received header: %s\n", peer->msg_cmd);
  peer_log(peer, "  msg size: %d\n", peer->waiting);

  return true;
}

static bool
peer_parse(hsk_peer_t *peer, uint8_t *msg, size_t msg_len) {
  if (!peer->msg_hdr)
    return peer_parse_hdr(peer, msg, msg_len);

  uint8_t hash[32];
  hsk_hash256(msg, msg_len, hash);

  if (memcmp(hash, peer->msg_sum, 4) != 0) {
    peer_log(peer, "invalid checksum: %s\n", peer->msg_cmd);
    goto fail;
  }

  uint8_t cmd = hsk_msg_cmd(peer->msg_cmd);

  if (cmd == MSG_UNKNOWN) {
    peer_log(peer, "unknown command: %s\n", peer->msg_cmd);
    goto success;
  }

  hsk_msg_t *m = hsk_msg_alloc(cmd);

  if (m == NULL)
    goto fail;

  if (!hsk_msg_decode(msg, msg_len, m)) {
    peer_log(peer, "error parsing msg: %s\n", peer->msg_cmd);
    free(m);
    goto fail;
  }

  peer_handle_msg(peer, m);
  hsk_msg_free(m);

  goto success;

  bool ret;
fail:
  ret = false;
  goto done;
success:
  ret = true;
  goto done;
done:
  peer->msg_hdr = false;
  peer->msg = xrealloc(peer->msg, 24);
  peer->pos = 0;
  peer->waiting = 24;
  memset(peer->msg_cmd, 0, sizeof peer->msg_cmd);
  memset(peer->msg_sum, 0, sizeof peer->msg_sum);
  return ret;
}

/*
 * UV behavior
 */

static void
write_cb(uv_write_t *req, int status) {
  hsk__write_data_t *wd = (hsk__write_data_t *)req->data;
  hsk_peer_t *peer = wd->peer;
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  if (wd->should_free) {
    free(wd->data);
    wd->data = NULL;
  }

  free(wd);
  req->data = NULL;

  free(req);

  if (status < 0) {
    peer_log(peer, "write error: %d\n", status);
    peer_destroy(peer);
    pool_refill(pool);
    return;
  }
}

static void
read_cb(uv_stream_t *stream, long int nread, const uv_buf_t *buf) {
  hsk_peer_t *peer = (hsk_peer_t *)stream->data;
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  if (nread < 0) {
    peer_log(peer, "read error: %d\n", nread);
    peer_destroy(peer);
    // Why is this causing an assertion failure??
    // pool_refill(pool);
    return;
  }

  peer_on_read(peer, (uint8_t *)buf->base, (size_t)nread);
}

static void
alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  hsk_peer_t *peer = (hsk_peer_t *)handle->data;
  buf->base = (char *)peer->rb;
  buf->len = HSK_BUFFER_SIZE;
}

static void
on_connect(uv_connect_t *conn, int status) {
  uv_tcp_t *socket = (uv_tcp_t *)conn->handle;
  hsk_peer_t *peer = (hsk_peer_t *)socket->data;
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  free(conn);

  if (status != 0) {
    peer_log(peer, "failed connecting: %d\n", status);
    peer_destroy(peer);
    pool_refill(pool);
    return;
  }

  peer->connected = true;
  peer_log(peer, "connected\n");

  status = uv_read_start((uv_stream_t *)socket, alloc_buffer, read_cb);

  if (status != 0) {
    peer_log(peer, "failed reading: %d\n", status);
    peer_destroy(peer);
    pool_refill(pool);
    return;
  }

  peer->reading = true;
}

static void
alloc_udp(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  hsk_pool_t *pool = (hsk_pool_t *)handle->data;
  buf->base = (char *)pool->ub;
  buf->len = HSK_UDP_BUFFER;
}

static void
send_cb(uv_udp_send_t *req, int status) {
  hsk__send_data_t *sd = (hsk__send_data_t *)req->data;
  hsk_pool_t *pool = sd->pool;

  if (sd->should_free) {
    free(sd->data);
    sd->data = NULL;
  }

  free(sd);
  req->data = NULL;

  free(req);

  if (status < 0) {
    printf("send error: %d\n", status);
    return;
  }
}

static void
recv_cb(
  uv_udp_t *socket,
  ssize_t nread,
  const uv_buf_t *buf,
  const struct sockaddr *addr,
  unsigned flags
) {
  hsk_pool_t *pool = (hsk_pool_t *)socket->data;

  if (nread < 0) {
    printf("udp read error: %d\n", nread);
    return;
  }

  // No more data to read.
  if (nread == 0 && addr == NULL) {
    printf("udp nodata\n");
    return;
  }

  if (addr == NULL) {
    printf("udp noaddr\n");
    return;
  }

  pool_on_recv(
    pool,
    (uint8_t *)buf->base,
    (size_t)nread,
    (struct sockaddr *)addr,
    (uint32_t)flags
  );
}

static void
alloc_udp2(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  hsk_pool_t *pool = (hsk_pool_t *)handle->data;
  buf->base = (char *)pool->ub2;
  buf->len = HSK_UDP_BUFFER;
}

static void
send_cb2(uv_udp_send_t *req, int status) {
  hsk__send_data_t *sd = (hsk__send_data_t *)req->data;
  hsk_pool_t *pool = sd->pool;

  if (sd->should_free) {
    free(sd->data);
    sd->data = NULL;
  }

  free(sd);
  req->data = NULL;

  free(req);

  if (status < 0) {
    printf("send error: %d\n", status);
    return;
  }
}

static void
recv_cb2(
  uv_udp_t *socket,
  ssize_t nread,
  const uv_buf_t *buf,
  const struct sockaddr *addr,
  unsigned flags
) {
  hsk_pool_t *pool = (hsk_pool_t *)socket->data;

  if (nread < 0) {
    printf("udp read error: %d\n", nread);
    return;
  }

  // No more data to read.
  if (nread == 0 && addr == NULL) {
    printf("udp nodata\n");
    return;
  }

  if (addr == NULL) {
    printf("udp noaddr\n");
    return;
  }

  pool_on_recv2(
    pool,
    (uint8_t *)buf->base,
    (size_t)nread,
    (struct sockaddr *)addr,
    (uint32_t)flags
  );
}

static void
respond_dns2(void *data, int32_t status, struct ub_result *result) {
  hsk__dns_req_t *dr = (hsk__dns_req_t *)data;
  pool_respond_dns2(dr->pool, dr->req, status, result, &dr->addr);
  ldns_pkt_free(dr->req);
  free(dr);
  ub_resolve_free(result);
}

/*
 * Main
 */

int
main() {
  uv_loop_t *loop = uv_default_loop();

  hsk_pool_t *pool = pool_alloc(loop);
  pool_refill(pool);

  if (uv_run(loop, UV_RUN_DEFAULT)) {
    abort();
    return 1;
  }

  pool_destroy(pool);
  uv_loop_close(loop);

  return 0;
}
