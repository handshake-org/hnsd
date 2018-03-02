#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "uv.h"
#include "ldns/ldns.h"
#include "unbound.h"

#include "hsk-addr.h"
#include "hsk-constants.h"
#include "hsk-resource.h"
#include "hsk-error.h"
#include "hsk-ec.h"
#include "hsk-hsig.h"
#include "dnssec.h"
#include "req.h"
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

/*
 * Templates
 */

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
hsk_rs_init(hsk_rs_t *ns, uv_loop_t *loop, struct sockaddr *stub) {
  if (!ns || !loop)
    return HSK_EBADARGS;

  struct ub_ctx *ub = NULL;
  hsk_ec_t *ec = NULL;

  ub = ub_ctx_create();

  if (!ub)
    goto fail;

  if (ub_ctx_async(ub, 1) != 0)
    goto fail;

  ec = hsk_ec_alloc();

  if (!ec)
    goto fail;

  ns->loop = loop;
  ns->ub = ub;
  ns->socket.data = (void *)ns;
  ns->poll.data = (void *)ns;
  ns->ec = ec;
  memset(ns->config_, 0x00, sizeof(ns->config_));
  ns->config = NULL;
  ns->stub = (struct sockaddr *)&ns->stub_ss;
  assert(hsk_sa_from_string(ns->stub, "127.0.0.1", HSK_NS_PORT));
  memset(ns->key_, 0x00, sizeof(ns->key_));
  ns->key = NULL;
  memset(ns->pubkey, 0x00, sizeof(ns->pubkey));
  memset(ns->read_buffer, 0x00, sizeof(ns->read_buffer));
  ns->bound = false;
  ns->receiving = false;
  ns->polling = false;

  if (stub) {
    if (!hsk_sa_copy(ns->stub, stub))
      return HSK_EFAILURE;

    if (!hsk_sa_localize(ns->stub))
      return HSK_EFAILURE;
  }

  return HSK_SUCCESS;

fail:
  if (ub)
    ub_ctx_delete(ub);

  if (ec)
    hsk_ec_free(ec);

  return HSK_ENOMEM;
}

void
hsk_rs_uninit(hsk_rs_t *ns) {
  if (!ns)
    return;

  ns->socket.data = NULL;
  ns->poll.data = NULL;

  if (ns->ec) {
    hsk_ec_free(ns->ec);
    ns->ec = NULL;
  }

  if (ns->ub) {
    ub_ctx_delete(ns->ub);
    ns->ub = NULL;
  }
}

bool
hsk_rs_set_config(hsk_rs_t *ns, char *config) {
  assert(ns);

  if (!config) {
    memset(ns->config_, 0x00, sizeof(ns->config_));
    ns->config = NULL;
    return true;
  }

  size_t size = strlen(config);

  if (size > 255)
    return false;

  memcpy(ns->config_, config, size + 1);
  ns->config = ns->config_;

  return true;
}

bool
hsk_rs_set_key(hsk_rs_t *ns, uint8_t *key) {
  assert(ns);

  if (!key) {
    memset(ns->key_, 0x00, sizeof(ns->key_));
    ns->key = NULL;
    return true;
  }

  if (!hsk_ec_create_pubkey(ns->ec, key, ns->pubkey))
    return false;

  memcpy(ns->key_, key, 32);
  ns->key = ns->key_;

  return true;
}

static bool
hsk_rs_inject_options(hsk_rs_t *ns) {
  if (ns->config) {
    if (ub_ctx_config(ns->ub, ns->config) != 0)
      return false;
  }

  if (ub_ctx_set_option(ns->ub, "do-tcp:", "no") != 0)
    return false;

  if (ub_ctx_set_option(ns->ub, "logfile:", "") != 0)
    return false;

  if (ub_ctx_set_option(ns->ub, "use-syslog:", "no") != 0)
    return false;

  if (ub_ctx_set_option(ns->ub, "domain-insecure:", ".") != 0)
    return false;

  if (ub_ctx_set_option(ns->ub, "root-hints:", "") != 0)
    return false;

  if (ub_ctx_set_option(ns->ub, "do-not-query-localhost:", "no") != 0)
    return false;

  char stub[HSK_MAX_HOST];

  if (!hsk_sa_to_string(ns->stub, stub, HSK_MAX_HOST, HSK_NS_PORT))
    return false;

  if (ub_ctx_set_stub(ns->ub, ".", stub, 0) != 0)
    return false;

  if (ub_ctx_add_ta(ns->ub, HSK_TRUST_ANCHOR) != 0)
    return false;

  if (ub_ctx_zone_add(ns->ub, ".", "nodefault") != 0)
    return false;

  hsk_rs_log(ns, "recursive nameserver pointing to: %s\n", stub);

  return true;
}

int32_t
hsk_rs_open(hsk_rs_t *ns, struct sockaddr *addr) {
  if (!ns || !addr)
    return HSK_EBADARGS;

  if (!hsk_rs_inject_options(ns))
    return HSK_EFAILURE;

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

  ub_ctx_delete(ns->ub);
  ns->ub = NULL;

  return HSK_SUCCESS;
}

hsk_rs_t *
hsk_rs_alloc(uv_loop_t *loop, struct sockaddr *stub) {
  hsk_rs_t *ns = malloc(sizeof(hsk_rs_t));

  if (!ns)
    return NULL;

  if (hsk_rs_init(ns, loop, stub) != HSK_SUCCESS) {
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
  hsk_dns_req_t *req = hsk_dns_req_create(data, data_len, addr);

  int32_t rc;
  bool result;
  uint8_t *wire;
  size_t wire_len;

  if (!req) {
    hsk_rs_log(ns, "failed processing dns request\n");
    return;
  }

  hsk_dns_req_print(req, "rs: ");

  req->ns = (void *)ns;

  rc = ub_resolve_async(
    ns->ub,
    req->name,
    req->type,
    req->class,
    (void *)req,
    after_resolve,
    NULL
  );

  if (rc == 0)
    return;

  hsk_rs_log(ns, "unbound error: %s\n", ub_strerror(rc));

  result = hsk_resource_to_servfail(
    req->id,
    req->name,
    req->type,
    req->edns,
    req->dnssec,
    &wire,
    &wire_len
  );

  if (!result) {
    hsk_rs_log(ns, "could not create servfail\n");
    goto done;
  }

  hsk_rs_send(ns, wire, wire_len, addr, true);

done:
  hsk_dns_req_free(req);
}

static void
hsk_rs_respond(
  hsk_rs_t *ns,
  hsk_dns_req_t *req,
  int32_t status,
  struct ub_result *result
) {
  ldns_pkt *pkt = NULL;
  uint8_t *wire;
  size_t wire_len;
  ldns_status rc;
  bool ok;

  if (status != 0) {
    hsk_rs_log(ns, "unbound error: %s\n", ub_strerror(status));
    goto fail;
  }

  hsk_rs_log(ns, "received answer for: %s\n", req->name);
  hsk_rs_log(ns, "  canonname: %s\n", result->canonname);
  hsk_rs_log(ns, "  rcode: %d\n", result->rcode);
  hsk_rs_log(ns, "  havedata: %d\n", result->havedata);
  hsk_rs_log(ns, "  nxdomain: %d\n", result->nxdomain);
  hsk_rs_log(ns, "  secure: %d\n", result->secure);
  hsk_rs_log(ns, "  bogus: %d\n", result->bogus);
  hsk_rs_log(ns, "  why_bogus: %s\n", result->why_bogus);

  uint8_t *data = result->answer_packet;
  size_t data_len = result->answer_len;

  // Deserialize to do some preprocessing.
  rc = ldns_wire2pkt(&pkt, data, data_len);

  if (rc != LDNS_STATUS_OK) {
    hsk_rs_log(ns,
      "failed parsing answer: %s\n",
      ldns_get_errorstr_by_id(rc));
    goto fail;
  }

  ldns_pkt_set_id(pkt, req->id);

  if (req->edns) {
    ldns_pkt_set_edns_udp_size(pkt, 4096);

    if (req->dnssec) {
      ldns_pkt_set_edns_do(pkt, 1);

      if (result->secure && !result->bogus)
        ldns_pkt_set_ad(pkt, 1);
      else
        ldns_pkt_set_ad(pkt, 0);

      if (!hsk_dnssec_clean(pkt, (ldns_rr_type)req->type))
        goto fail;
    }
  }

  // Reserialize once we're done.
  rc = ldns_pkt2wire(&wire, pkt, &wire_len);

  if (rc != LDNS_STATUS_OK) {
    hsk_rs_log(ns,
      "could not serialize response: %s\n",
      ldns_get_errorstr_by_id(rc));
    goto fail;
  }

  if (ns->key) {
    if (!hsk_hsig_sign_msg(ns->ec, ns->key, &wire, &wire_len, req->nonce)) {
      hsk_rs_log(ns, "could not sign response\n");
      goto fail;
    }
  }

  ldns_pkt_free(pkt);

  goto done;

fail:
  if (pkt)
    ldns_pkt_free(pkt);

  ok = hsk_resource_to_servfail(
    req->id,
    req->name,
    req->type,
    req->edns,
    req->dnssec,
    &wire,
    &wire_len
  );

  if (!ok) {
    hsk_rs_log(ns, "could not create servfail\n");
    return;
  }

done:
  hsk_rs_send(ns, wire, wire_len, req->addr, true);
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
    hsk_rs_log(ns, "udp read error: %s\n", uv_strerror(nread));
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
  hsk_dns_req_t *req = (hsk_dns_req_t *)data;
  hsk_rs_respond((hsk_rs_t *)req->ns, req, status, result);
  hsk_dns_req_free(req);
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
