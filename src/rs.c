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
#include "unbound.h"

#include "hsk-addr.h"
#include "hsk-constants.h"
#include "hsk-error.h"
#include "hsk-ec.h"
#include "hsk-hsig.h"
#include "rs.h"
#include "utils.h"

/*
 * Types
 */

typedef struct {
  hsk_rs_t *ns;
  void *data;
  bool should_free;
} hsk_send_data_t;

typedef struct {
  hsk_rs_t *ns;
  ldns_pkt *req;
  uint8_t nonce[32];
  struct sockaddr_storage ss;
  struct sockaddr *addr;
} hsk_dns_req_t;

/*
 * Templates
 */

static int32_t
hsk_rs_init_unbound(hsk_rs_t *ns, struct sockaddr *addr);

static void
hsk_rs_log(hsk_rs_t *ns, const char *fmt, ...);

static int32_t
hsk_rs_send(
  hsk_rs_t *,
  uint8_t *,
  size_t,
  struct sockaddr *,
  bool
);

static void
alloc_buffer(uv_handle_t *, size_t, uv_buf_t *);

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
after_poll(uv_poll_t *, int, int);

static void
after_resolve(void *, int32_t, struct ub_result *);

static void
after_close(uv_handle_t *);

/*
 * Recursive NS
 */

int32_t
hsk_rs_init(hsk_rs_t *ns, uv_loop_t *loop, struct sockaddr *addr) {
  if (!ns || !loop || !addr)
    return HSK_EBADARGS;

  hsk_ec_t *ec = hsk_ec_alloc();

  if (!ec)
    return HSK_ENOMEM;

  ns->loop = loop;
  ns->ub = NULL;
  ns->socket.data = (void *)ns;
  ns->poll.data = (void *)ns;
  ns->ec = ec;
  ns->key = NULL;
  memset(ns->_key, 0, sizeof(ns->_key));
  memset(ns->pubkey, 0, sizeof(ns->pubkey));
  memset(ns->read_buffer, 0, sizeof(ns->read_buffer));
  ns->bound = false;
  ns->receiving = false;
  ns->polling = false;

  return hsk_rs_init_unbound(ns, addr);
}

static int32_t
hsk_rs_init_unbound(hsk_rs_t *ns, struct sockaddr *addr) {
  if (!ns || !addr)
    return HSK_EBADARGS;

  ns->ub = ub_ctx_create();

  if (!ns->ub)
    return HSK_ENOMEM;

  assert(ub_ctx_async(ns->ub, 1) == 0);

  assert(ub_ctx_set_option(ns->ub, "do-tcp:", "no") == 0);
  assert(ub_ctx_set_option(ns->ub, "logfile:", "") == 0);
  assert(ub_ctx_set_option(ns->ub, "use-syslog:", "no") == 0);
  assert(ub_ctx_set_option(ns->ub, "domain-insecure:", ".") == 0);
  assert(ub_ctx_set_option(ns->ub, "root-hints:", "") == 0);
  assert(ub_ctx_set_option(ns->ub, "do-not-query-localhost:", "no") == 0);

  char stub[HSK_MAX_HOST];

  if (!hsk_sa_to_string(addr, stub, HSK_MAX_HOST, HSK_NS_PORT))
    return HSK_EFAILURE;

  assert(ub_ctx_set_stub(ns->ub, ".", stub, 0) == 0);
  assert(ub_ctx_add_ta(ns->ub, HSK_TRUST_ANCHOR) == 0);
  assert(ub_ctx_zone_add(ns->ub, ".", "nodefault") == 0);

  hsk_rs_log(ns, "recursive nameserver pointing to: %s\n", stub);

  return HSK_SUCCESS;
}

void
hsk_rs_uninit(hsk_rs_t *ns) {
  if (!ns)
    return;

  ns->socket.data = NULL;
  ns->poll.data = NULL;

  if (ns->ub) {
    ub_ctx_delete(ns->ub);
    ns->ub = NULL;
  }
}

bool
hsk_rs_set_key(hsk_rs_t *ns, uint8_t *key) {
  assert(ns && key);

  if (!hsk_ec_create_pubkey(ns->ec, key, ns->pubkey))
    return false;

  memcpy(ns->_key, key, 32);
  ns->key = ns->_key;

  return true;
}

int32_t
hsk_rs_open(hsk_rs_t *ns, struct sockaddr *addr) {
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

  if (uv_poll_init(ns->loop, &ns->poll, ub_fd(ns->ub)) != 0)
    return HSK_EFAILURE;

  ns->polling = true;
  ns->poll.data = (void *)ns;

  if (uv_poll_start(&ns->poll, UV_READABLE, after_poll) != 0)
    return HSK_EFAILURE;

  char host[HSK_MAX_HOST];
  assert(hsk_sa_to_string(addr, host, HSK_MAX_HOST, HSK_NS_PORT));

  hsk_rs_log(ns, "recursive nameserver listening on: %s\n", host);

  return HSK_SUCCESS;
}

int32_t
hsk_rs_close(hsk_rs_t *ns) {
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

  if (ns->polling) {
    if (uv_poll_stop(&ns->poll) != 0)
      return HSK_EFAILURE;
    ns->polling = false;
  }

  ns->socket.data = NULL;
  ns->poll.data = NULL;

  if (ns->ub) {
    ub_ctx_delete(ns->ub);
    ns->ub = NULL;
  }

  return HSK_SUCCESS;
}

hsk_rs_t *
hsk_rs_alloc(uv_loop_t *loop, struct sockaddr *addr) {
  hsk_rs_t *ns = malloc(sizeof(hsk_rs_t));

  if (!ns)
    return NULL;

  if (hsk_rs_init(ns, loop, addr) != HSK_SUCCESS) {
    free(ns);
    return NULL;
  }

  return ns;
}

void
hsk_rs_free(hsk_rs_t *ns) {
  if (!ns)
    return;

  hsk_rs_uninit(ns);
  free(ns);
}

int32_t
hsk_rs_destroy(hsk_rs_t *ns) {
  if (!ns)
    return HSK_EBADARGS;

  int32_t rc = hsk_rs_close(ns);

  if (rc != 0)
    return rc;

  hsk_rs_free(ns);

  return HSK_SUCCESS;
}

static void
hsk_rs_log(hsk_rs_t *ns, const char *fmt, ...) {
  printf("rs: ");

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

static void
hsk_rs_onrecv(
  hsk_rs_t *ns,
  uint8_t *data,
  size_t data_len,
  struct sockaddr *addr,
  uint32_t flags
) {
  ldns_pkt *req;
  ldns_status rc = ldns_wire2pkt(&req, data, data_len);

  if (rc != LDNS_STATUS_OK) {
    hsk_rs_log(ns, "bad dns message: %s\n", ldns_get_errorstr_by_id(rc));
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

  hsk_rs_log(ns, "received recursive dns query:\n");
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

  if (!name) {
    ldns_pkt_free(req);
    return;
  }

  uint16_t type = (uint16_t)rrtype;
  uint16_t class = (uint16_t)rrclass;

  hsk_dns_req_t *dr = (hsk_dns_req_t *)calloc(1, sizeof(hsk_dns_req_t));

  if (!dr) {
    free(name);
    ldns_pkt_free(req);
    return;
  }

  dr->ns = ns;
  dr->req = req;
  dr->addr = (struct sockaddr *)&dr->ss;
  hsk_sa_copy(dr->addr, addr);

  if (!hsk_hsig_get_nonce(data, data_len, dr->nonce))
    hsk_rs_log(ns, "no nonce in dns request\n");

  int32_t r = ub_resolve_async(
    ns->ub,
    name,
    type,
    class,
    (void *)dr,
    after_resolve,
    NULL
  );

  free(name);

  if (r != 0) {
    hsk_rs_log(ns, "resolve error: %s\n", ub_strerror(r));
    return;
  }
}

static void
hsk_rs_respond(
  hsk_rs_t *ns,
  ldns_pkt *req,
  uint8_t *nonce,
  int32_t status,
  struct ub_result *result,
  struct sockaddr *addr
) {
  if (status != 0) {
    hsk_rs_log(ns, "resolve error: %s\n", ub_strerror(status));
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
    hsk_rs_log(ns, "bad dns message: %s\n", ldns_get_errorstr_by_id(rc));
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

  if (r != LDNS_STATUS_OK) {
    hsk_rs_log(ns, "could not serialize response\n");
    return;
  }

  if (ns->key) {
    uint8_t *data;
    size_t data_len;

    bool result = hsk_hsig_sign(
      ns->ec,
      ns->key,
      wire,
      wire_len,
      nonce,
      &data,
      &data_len
    );

    if (!result) {
      free(wire);
      hsk_rs_log(ns, "could not sign response\n");
      return;
    }

    hsk_rs_send(ns, data, data_len, addr, true);
    return;
  }

  hsk_rs_send(ns, wire, wire_len, addr, true);
}

static int32_t
hsk_rs_send(
  hsk_rs_t *ns,
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
    hsk_rs_log(ns, "failed sending: %d\n", status);
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
  hsk_rs_t *ns = (hsk_rs_t *)handle->data;

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
  hsk_rs_t *ns = sd->ns;

  if (sd->should_free && sd->data)
    free(sd->data);

  free(sd);
  free(req);

  if (!ns)
    return;

  if (status != 0) {
    hsk_rs_log(ns, "send error: %d\n", status);
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
  hsk_rs_t *ns = (hsk_rs_t *)socket->data;

  if (!ns)
    return;

  if (nread < 0) {
    hsk_rs_log(ns, "udp read error: %d\n", nread);
    return;
  }

  // No more data to read.
  if (nread == 0 && addr == NULL) {
    hsk_rs_log(ns, "udp nodata\n");
    return;
  }

  if (addr == NULL) {
    hsk_rs_log(ns, "udp noaddr\n");
    return;
  }

  hsk_rs_onrecv(
    ns,
    (uint8_t *)buf->base,
    (size_t)nread,
    (struct sockaddr *)addr,
    (uint32_t)flags
  );
}

static void
after_poll(uv_poll_t *handle, int status, int events) {
  hsk_rs_t *ns = (hsk_rs_t *)handle->data;

  if (!ns)
    return;

  if (status == 0 && (events & UV_READABLE))
    ub_process(ns->ub);
}

static void
after_resolve(void *data, int32_t status, struct ub_result *result) {
  hsk_dns_req_t *dr = (hsk_dns_req_t *)data;

  if (!dr->ns)
    return;

  hsk_rs_respond(dr->ns, dr->req, dr->nonce, status, result, dr->addr);
  ldns_pkt_free(dr->req);
  free(dr);
  ub_resolve_free(result);
}

static void
after_close(uv_handle_t *handle) {
  hsk_rs_t *ns = (hsk_rs_t *)handle->data;
  // assert(ns);
  // handle->data = NULL;
  // ns->bound = false;
  // hsk_rs_free(peer);
}
