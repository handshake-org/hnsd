#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "uv.h"
#include "ldns/ldns.h"

#include "hsk-addr.h"
#include "hsk-constants.h"
#include "hsk-ec.h"
#include "hsk-error.h"
#include "hsk-resource.h"
#include "ns.h"
#include "pool.h"

/*
 * Types
 */

typedef struct {
  hsk_ns_t *ns;
  void *data;
  bool should_free;
} hsk_send_data_t;

typedef struct {
  hsk_ns_t *ns;
  ldns_pkt *req;
  struct sockaddr addr;
  char fqdn[256];
} hsk_dns_req_t;

/*
 * Templates
 */

static void
hsk_ns_log(hsk_ns_t *, const char *, ...);

static void
hsk_ns_respond(
  char *,
  int32_t,
  bool,
  uint8_t *,
  size_t,
  void *
);

static int32_t
hsk_ns_send(
  hsk_ns_t *,
  uint8_t *,
  size_t,
  struct sockaddr *,
  bool
);

static void
alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf);

static void
after_send(uv_udp_send_t *, int);

static void
after_recv(
  uv_udp_t *,
  ssize_t,
  const uv_buf_t *,
  const struct sockaddr *,
  unsigned
);


static void
after_close(uv_handle_t *);

/*
 * Root Nameserver
 */

int32_t
hsk_ns_init(hsk_ns_t *ns, uv_loop_t *loop, hsk_pool_t *pool) {
  if (!ns || !pool)
    return HSK_EBADARGS;

  hsk_ec_t *ec = hsk_ec_alloc();

  if (!ec)
    return HSK_ENOMEM;

  ns->loop = loop;
  ns->pool = pool;
  ns->ip = NULL;
  hsk_addr_init(&ns->_ip);
  ns->socket.data = (void *)ns;
  ns->ec = ec;
  ns->key = NULL;
  memset(ns->_key, 0, sizeof(ns->_key));
  memset(ns->pubkey, 0, sizeof(ns->pubkey));
  memset(ns->read_buffer, 0, sizeof(ns->read_buffer));
  ns->bound = false;
  ns->receiving = false;

  return HSK_SUCCESS;
}

void
hsk_ns_uninit(hsk_ns_t *ns) {
  if (!ns)
    return;
  ns->socket.data = NULL;
}

void
hsk_ns_set_ip(hsk_ns_t *ns, struct sockaddr *addr) {
  if (hsk_addr_from_sa(&ns->_ip, addr))
    ns->ip = &ns->_ip;
}

bool
hsk_ns_set_key(hsk_ns_t *ns, uint8_t *key) {
  assert(ns && key);

  if (!hsk_ec_create_pubkey(ns->ec, key, ns->pubkey))
    return false;

  memcpy(ns->_key, key, 32);
  ns->key = ns->_key;

  return true;
}

int32_t
hsk_ns_open(hsk_ns_t *ns, struct sockaddr *addr) {
  if (!ns || !addr)
    return HSK_EBADARGS;

  if (uv_udp_init(ns->loop, &ns->socket) != 0)
    return HSK_EFAILURE;

  ns->socket.data = (void *)ns;

  if (uv_udp_bind(&ns->socket, addr, 0) != 0)
    return HSK_EFAILURE;

  ns->bound = true;

  int32_t value = sizeof(ns->read_buffer);

  if (uv_send_buffer_size((uv_handle_t *)&ns->socket, &value) != 0)
    return HSK_EFAILURE;

  if (uv_recv_buffer_size((uv_handle_t *)&ns->socket, &value) != 0)
    return HSK_EFAILURE;

  if (uv_udp_recv_start(&ns->socket, alloc_buffer, after_recv) != 0)
    return HSK_EFAILURE;

  ns->receiving = true;

  if (!ns->ip)
    hsk_ns_set_ip(ns, addr);

  char host[HSK_MAX_HOST];
  assert(hsk_sa_to_string(addr, host, HSK_MAX_HOST, HSK_NS_PORT));

  hsk_ns_log(ns, "root nameserver listening on: %s\n", host);

  return HSK_SUCCESS;
}

int32_t
hsk_ns_close(hsk_ns_t *ns) {
  if (!ns)
    return HSK_EBADARGS;

  if (ns->receiving) {
    if (uv_udp_recv_stop(&ns->socket) != 0)
      return HSK_EFAILURE;
    ns->receiving = false;
  }

  if (ns->bound) {
    uv_close((uv_handle_t *)&ns->socket, after_close);
    ns->bound = false;
  }

  ns->socket.data = NULL;

  return HSK_SUCCESS;
}

hsk_ns_t *
hsk_ns_alloc(uv_loop_t *loop, hsk_pool_t *pool) {
  hsk_ns_t *ns = malloc(sizeof(hsk_ns_t));

  if (!ns)
    return NULL;

  if (hsk_ns_init(ns, loop, pool) != HSK_SUCCESS) {
    free(ns);
    return NULL;
  }

  return ns;
}

void
hsk_ns_free(hsk_ns_t *ns) {
  if (!ns)
    return;

  hsk_ns_uninit(ns);
  free(ns);
}

int32_t
hsk_ns_destroy(hsk_ns_t *ns) {
  if (!ns)
    return HSK_EBADARGS;

  int32_t rc = hsk_ns_close(ns);

  if (rc != 0)
    return rc;

  hsk_ns_free(ns);

  return HSK_SUCCESS;
}

static void
hsk_ns_log(hsk_ns_t *ns, const char *fmt, ...) {
  printf("ns: ");

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

static void
hsk_ns_onrecv(
  hsk_ns_t *ns,
  uint8_t *data,
  size_t data_len,
  struct sockaddr *addr,
  uint32_t flags
) {
  ldns_pkt *req;
  ldns_status rc = ldns_wire2pkt(&req, data, data_len);

  if (rc != LDNS_STATUS_OK) {
    hsk_ns_log(ns, "bad dns message: %s\n", ldns_get_errorstr_by_id(rc));
    return;
  }

  ldns_pkt_opcode opcode = ldns_pkt_get_opcode(req);
  ldns_pkt_rcode rcode = ldns_pkt_get_rcode(req);
  ldns_rr_list *qd = ldns_pkt_question(req);
  ldns_rr_list *an = ldns_pkt_answer(req);
  ldns_rr_list *ns_ = ldns_pkt_authority(req);

  if (opcode != LDNS_PACKET_QUERY
      || rcode != LDNS_RCODE_NOERROR
      || ldns_rr_list_rr_count(qd) != 1
      || ldns_rr_list_rr_count(an) != 0
      || ldns_rr_list_rr_count(ns_) != 0) {
    ldns_pkt_free(req);
    return;
  }

  // Grab the first question.
  ldns_rr *qs = ldns_rr_list_rr(qd, 0);

  hsk_ns_log(ns, "received dns query:\n");
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

  if (!fqdn) {
    ldns_pkt_free(req);
    return;
  }

  size_t size = strlen(fqdn);

  if (size == 0 || size > 255 || fqdn[size - 1] != '.') {
    free(fqdn);
    ldns_pkt_free(req);
    return;
  }

  // Authoritative.
  if (size == 1) {
    bool edns = ldns_pkt_edns_udp_size(req) == 4096;
    bool dnssec = ldns_pkt_edns_do(req);

    free(fqdn);
    ldns_pkt_free(req);

    uint8_t *wire;
    size_t wire_len;

    bool result = hsk_resource_root(
      id,
      type,
      edns,
      dnssec,
      ns->ip,
      &wire,
      &wire_len
    );

    if (!result)
      return;

    hsk_ns_send(ns, wire, wire_len, addr, true);

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

  hsk_dns_req_t *dr = malloc(sizeof(hsk_dns_req_t));

  if (!dr) {
    free(fqdn);
    ldns_pkt_free(req);
    return;
  }

  dr->ns = ns;
  dr->req = req;
  memcpy((void *)&dr->addr, (void *)addr, sizeof(struct sockaddr));
  memcpy(dr->fqdn, fqdn, size + 1);
  free(fqdn);

  int32_t r = hsk_pool_resolve(ns->pool, name, hsk_ns_respond, (void *)dr);

  if (r != HSK_SUCCESS)
    hsk_ns_log(ns, "resolve error: %d\n", r);
}

static void
hsk_ns_respond(
  char *name,
  int32_t status,
  bool exists,
  uint8_t *data,
  size_t data_len,
  void *arg
) {
  hsk_dns_req_t *dr = (hsk_dns_req_t *)arg;
  hsk_ns_t *ns = dr->ns;
  ldns_pkt *req = dr->req;
  struct sockaddr *addr = &dr->addr;
  char *fqdn = dr->fqdn;

  if (status != HSK_SUCCESS) {
    hsk_ns_log(ns, "resolve response error: %d\n", status);
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
  if (!exists) {
    if (!hsk_resource_to_nx(id, fqdn, type, edns, dnssec, &wire, &wire_len)) {
      free(dr);
      return;
    }
    hsk_ns_send(ns, wire, wire_len, addr, true);
    free(dr);
    return;
  }

  hsk_resource_t *rs;

  if (!hsk_resource_decode(data, data_len, &rs)) {
    ldns_pkt_free(req);
    free(dr);
    return;
  }

  if (!hsk_resource_to_dns(rs, id, fqdn, type, edns, dnssec, &wire, &wire_len)) {
    hsk_resource_free(rs);
    free(dr);
    return;
  }

  hsk_resource_free(rs);

  hsk_ns_send(ns, wire, wire_len, addr, true);

  free(dr);
}

int32_t
hsk_ns_send(
  hsk_ns_t *ns,
  uint8_t *data,
  size_t data_len,
  struct sockaddr *addr,
  bool should_free
) {
  int32_t rc = HSK_SUCCESS;
  hsk_send_data_t *sd = NULL;
  uv_udp_send_t *req = NULL;

  sd = (hsk_send_data_t *)malloc(sizeof(hsk_send_data_t));

  if (!sd) {
    rc = HSK_ENOMEM;
    goto fail;
  }

  req = (uv_udp_send_t *)malloc(sizeof(uv_udp_send_t));

  if (!req) {
    rc = HSK_ENOMEM;
    goto fail;
  }

  sd->ns = ns;
  sd->data = (void *)data;
  sd->should_free = should_free;

  req->data = (void *)sd;

  uv_buf_t bufs[] = {
    { .base = data, .len = data_len }
  };

  int status = uv_udp_send(req, &ns->socket, bufs, 1, addr, after_send);

  if (status != 0) {
    hsk_ns_log(ns, "failed sending: %d\n", status);
    rc = HSK_EFAILURE;
    goto fail;
  }

  return rc;

fail:
  if (sd)
    free(sd);

  if (req)
    free(req);

  if (should_free)
    free(data);

  return rc;
}

/*
 * UV behavior
 */

static void
alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  hsk_ns_t *ns = (hsk_ns_t *)handle->data;

  if (!ns) {
    buf->base = NULL;
    buf->len = 0;
    return;
  }

  buf->base = (char *)ns->read_buffer;
  buf->len = sizeof(ns->read_buffer);
}

static void
after_send(uv_udp_send_t *req, int status) {
  hsk_send_data_t *sd = (hsk_send_data_t *)req->data;
  hsk_ns_t *ns = sd->ns;

  if (sd->should_free && sd->data)
    free(sd->data);

  free(sd);
  free(req);

  if (!ns)
    return;

  if (status != 0) {
    hsk_ns_log(ns, "send error: %d\n", status);
    return;
  }
}

static void
after_recv(
  uv_udp_t *socket,
  ssize_t nread,
  const uv_buf_t *buf,
  const struct sockaddr *addr,
  unsigned flags
) {
  hsk_ns_t *ns = (hsk_ns_t *)socket->data;

  if (!ns)
    return;

  if (nread < 0) {
    hsk_ns_log(ns, "udp read error: %d\n", nread);
    return;
  }

  // No more data to read.
  if (nread == 0 && addr == NULL) {
    hsk_ns_log(ns, "udp nodata\n");
    return;
  }

  if (addr == NULL) {
    hsk_ns_log(ns, "udp noaddr\n");
    return;
  }

  hsk_ns_onrecv(
    ns,
    (uint8_t *)buf->base,
    (size_t)nread,
    (struct sockaddr *)addr,
    (uint32_t)flags
  );
}

static void
after_close(uv_handle_t *handle) {
  hsk_ns_t *ns = (hsk_ns_t *)handle->data;
  // assert(ns);
  // handle->data = NULL;
  // ns->bound = false;
  // hsk_ns_free(peer);
}
