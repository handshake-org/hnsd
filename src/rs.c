#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unbound.h>

#include "addr.h"
#include "constants.h"
#include "dns.h"
#include "dnssec.h"
#include "ec.h"
#include "error.h"
#include "platform-net.h"
#include "resource.h"
#include "req.h"
#include "rs.h"
#include "utils.h"
#include "uv.h"

/*
 * Types
 */

typedef struct {
  hsk_rs_t *ns;
  void *data;
  bool should_free;
} hsk_send_data_t;

/*
 * Prototypes
 */

static void
hsk_rs_log(hsk_rs_t *ns, const char *fmt, ...);

static int
hsk_rs_send(
  hsk_rs_t *ns,
  uint8_t *data,
  size_t data_len,
  const struct sockaddr *addr,
  bool should_free
);

static void
alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf);

static void
after_worker_stop(void *data);

static void
after_send(uv_udp_send_t *req, int status);

static void
after_recv(
  uv_udp_t *socket,
  ssize_t nread,
  const uv_buf_t *buf,
  const struct sockaddr *addr,
  unsigned flags
);

static void
after_resolve(void *data, int status, struct ub_result *result);

/*
 * Recursive NS
 */

int
hsk_rs_init(hsk_rs_t *ns, const uv_loop_t *loop, const struct sockaddr *stub) {
  if (!ns || !loop)
    return HSK_EBADARGS;

  int err = HSK_ENOMEM;
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

  ns->loop = (uv_loop_t *)loop;
  ns->ub = ub;
  ns->socket = NULL;
  ns->rs_worker = NULL;
  ns->ec = ec;
  ns->config = NULL;
  ns->stub = (struct sockaddr *)&ns->stub_;
  assert(hsk_sa_from_string(ns->stub, "127.0.0.1", HSK_NS_PORT));
  memset(ns->key_, 0x00, sizeof(ns->key_));
  ns->key = NULL;
  memset(ns->pubkey, 0x00, sizeof(ns->pubkey));
  memset(ns->read_buffer, 0x00, sizeof(ns->read_buffer));
  ns->receiving = false;
  ns->stop_callback = NULL;

  if (stub) {
    err = HSK_EFAILURE;

    if (!hsk_sa_copy(ns->stub, stub))
      goto fail;

    if (!hsk_sa_localize(ns->stub))
      goto fail;
  }

  return HSK_SUCCESS;

fail:
  if (ub)
    ub_ctx_delete(ub);

  if (ec)
    hsk_ec_free(ec);

  return err;
}

void
hsk_rs_uninit(hsk_rs_t *ns) {
  if (!ns)
    return;

  if (ns->ec) {
    hsk_ec_free(ns->ec);
    ns->ec = NULL;
  }

  if (ns->ub) {
    ub_ctx_delete(ns->ub);
    ns->ub = NULL;
  }

  if (ns->config) {
    free(ns->config);
    ns->config = NULL;
  }
}

bool
hsk_rs_set_config(hsk_rs_t *ns, const char *config) {
  assert(ns);

  if (!config) {
    ns->config = NULL;
    return true;
  }

  if (strlen(config) == 0)
    return false;

  ns->config = strdup(config);

  if (!ns->config)
    return false;

  return true;
}

bool
hsk_rs_set_key(hsk_rs_t *ns, const uint8_t *key) {
  assert(ns);

  if (!key) {
    memset(ns->key_, 0x00, sizeof(ns->key_));
    ns->key = NULL;
    memset(ns->pubkey, 0x00, sizeof(ns->pubkey));
    return true;
  }

  if (!hsk_ec_create_pubkey(ns->ec, key, ns->pubkey))
    return false;

  memcpy(&ns->key_[0], key, 32);
  ns->key = &ns->key_[0];

  return true;
}

static bool
hsk_rs_inject_options(hsk_rs_t *ns) {
  if (ns->config) {
    if (ub_ctx_config(ns->ub, ns->config) != 0)
      return false;
  }

  if (ub_ctx_set_option(ns->ub, "logfile:", "") != 0)
    return false;

  if (ub_ctx_set_option(ns->ub, "use-syslog:", "no") != 0)
    return false;

  ub_ctx_set_option(ns->ub, "trust-anchor-signaling:", "no");

  if (ub_ctx_set_option(ns->ub, "edns-buffer-size:", "4096") != 0)
    return false;

  if (ub_ctx_set_option(ns->ub, "max-udp-size:", "4096") != 0)
    return false;

  ub_ctx_set_option(ns->ub, "qname-minimisation:", "yes");

  if (ub_ctx_set_option(ns->ub, "root-hints:", "") != 0)
    return false;

  if (ub_ctx_set_option(ns->ub, "do-tcp:", "no") != 0)
    return false;

  char stub[HSK_MAX_HOST];

  if (!hsk_sa_to_at(ns->stub, stub, HSK_MAX_HOST, HSK_NS_PORT))
    return false;

  if (ub_ctx_set_stub(ns->ub, ".", stub, 0) != 0)
    return false;

  if (ub_ctx_add_ta(ns->ub, HSK_TRUST_ANCHOR) != 0)
    return false;

  if (ub_ctx_zone_add(ns->ub, ".", "nodefault") != 0
      && ub_ctx_zone_add(ns->ub, ".", "transparent") != 0) {
    return false;
  }

  // Use a thread instead of forking for libunbound's async work.  Threads work
  // on all platforms, but forking does not work on Windows.
  ub_ctx_async(ns->ub, 1);

  hsk_rs_log(ns, "recursive nameserver pointing to: %s\n", stub);

  return true;
}

int
hsk_rs_open(hsk_rs_t *ns, const struct sockaddr *addr) {
  if (!ns || !addr)
    return HSK_EBADARGS;

  if (!hsk_rs_inject_options(ns))
    return HSK_EFAILURE;

  ns->socket = malloc(sizeof(uv_udp_t));
  if (!ns->socket)
    return HSK_ENOMEM;

  if (uv_udp_init(ns->loop, ns->socket) != 0)
    return HSK_EFAILURE;

  ns->socket->data = (void *)ns;

  if (uv_udp_bind(ns->socket, addr, 0) != 0)
    return HSK_EFAILURE;

  int value = sizeof(ns->read_buffer);

  if (uv_send_buffer_size((uv_handle_t *)ns->socket, &value) != 0)
    return HSK_EFAILURE;

  if (uv_recv_buffer_size((uv_handle_t *)ns->socket, &value) != 0)
    return HSK_EFAILURE;

  if (uv_udp_recv_start(ns->socket, alloc_buffer, after_recv) != 0)
    return HSK_EFAILURE;

  ns->receiving = true;

  ns->rs_worker = hsk_rs_worker_alloc(ns->loop, (void *)ns, after_worker_stop);
  if (!ns->rs_worker)
    return HSK_EFAILURE;

  if (hsk_rs_worker_open(ns->rs_worker, ns->ub) != HSK_SUCCESS)
    return HSK_EFAILURE;

  char host[HSK_MAX_HOST];
  assert(hsk_sa_to_string(addr, host, HSK_MAX_HOST, HSK_NS_PORT));

  hsk_rs_log(ns, "recursive nameserver listening on: %s\n", host);

  return HSK_SUCCESS;
}

int
hsk_rs_close(hsk_rs_t *ns, void *stop_data, void (*stop_callback)(void *)) {
  if (!ns)
    return HSK_EBADARGS;

  ns->stop_data = stop_data;
  ns->stop_callback = stop_callback;

  // If the worker is running, stop it, after_worker_stop is called
  // asynchronously.  Otherwise, just call it directly.
  if(ns->rs_worker && hsk_rs_worker_is_open(ns->rs_worker))
    hsk_rs_worker_close(ns->rs_worker);
  else
    after_worker_stop((void *)ns);

  return HSK_SUCCESS;
}

hsk_rs_t *
hsk_rs_alloc(const uv_loop_t *loop, const struct sockaddr *stub) {
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
  const uint8_t *data,
  size_t data_len,
  const struct sockaddr *addr,
  uint32_t flags
) {
  hsk_dns_req_t *req = hsk_dns_req_create(data, data_len, addr);

  int rc;
  uint8_t *wire = NULL;
  size_t wire_len = 0;
  hsk_dns_msg_t *msg = NULL;

  if (!req) {
    hsk_rs_log(ns, "failed processing dns request\n");
    return;
  }

  hsk_dns_req_print(req, "rs: ");

  req->ns = (void *)ns;

  if (req->type == HSK_DNS_ANY) {
    msg = hsk_resource_to_notimp();
    goto fail;
  }

  // Unbound's name resolution API expects a single null-terminated string.
  // Since 0x00 is a valid byte mid-label in wire format we need to
  // convert `req->name` to presentation format (i.e. "\000" for 0x00)
  if (!hsk_dns_name_to_string(req->name, req->namestr))
    goto fail;

  rc = hsk_rs_worker_resolve(
    ns->rs_worker,
    req->namestr,
    req->type,
    req->class,
    (void *)req,
    after_resolve
  );

  if (rc == HSK_SUCCESS)
    return;

  hsk_rs_log(ns, "resolve error: %s\n", hsk_strerror(rc));

  msg = hsk_resource_to_servfail();

fail:
  if (!msg) {
    hsk_rs_log(ns, "could not create servfail\n");
    goto done;
  }

  if (!hsk_dns_msg_finalize(&msg, req, ns->ec, ns->key, &wire, &wire_len)) {
    hsk_rs_log(ns, "could not finalize msg\n");
    goto done;
  }

  hsk_rs_send(ns, wire, wire_len, addr, true);

done:
  hsk_dns_req_free(req);
}

static void
hsk_rs_respond(
  hsk_rs_t *ns,
  const hsk_dns_req_t *req,
  int status,
  const struct ub_result *result
) {
  hsk_dns_msg_t *msg = NULL;
  uint8_t *wire = NULL;
  size_t wire_len = 0;

  if (status != 0) {
    hsk_rs_log(ns, "unbound error: %s\n", ub_strerror(status));
    goto fail;
  }

  char namestr[HSK_DNS_MAX_NAME_STRING] = {0};
  assert(hsk_dns_name_to_string(req->name, namestr));
  hsk_rs_log(ns, "received answer for: %s\n", namestr);

  if (result->canonname)
    hsk_rs_log(ns, "  canonname: %s\n", result->canonname);

  hsk_rs_log(ns, "  rcode: %u\n", result->rcode);
  hsk_rs_log(ns, "  havedata: %d\n", result->havedata);
  hsk_rs_log(ns, "  nxdomain: %d\n", result->nxdomain);
  hsk_rs_log(ns, "  secure: %d\n", result->secure);
  hsk_rs_log(ns, "  bogus: %d\n", result->bogus);

  if (result->why_bogus)
    hsk_rs_log(ns, "  why_bogus: %s\n", result->why_bogus);

  uint8_t *data = result->answer_packet;
  size_t data_len = result->answer_len;

  // Deserialize to do some preprocessing.
  if (!hsk_dns_msg_decode(data, data_len, &msg)) {
    hsk_rs_log(ns, "failed parsing answer\n");
    goto fail;
  }

  // "Clean" the packet.
  msg->flags = 0;
  msg->opcode = HSK_DNS_QUERY;
  msg->code = result->rcode;
  msg->flags |= HSK_DNS_RA;

  if (result->secure && !result->bogus)
    msg->flags |= HSK_DNS_AD;

  // Strip out non-answer sections.
  if (msg->an.size > 0) {
    while (msg->ns.size > 0) {
      hsk_dns_rr_t *rr = hsk_dns_rrs_pop(&msg->ns);
      hsk_dns_rr_free(rr);
    }

    while (msg->ar.size > 0) {
      hsk_dns_rr_t *rr = hsk_dns_rrs_pop(&msg->ar);
      hsk_dns_rr_free(rr);
    }
  }

  if (!req->dnssec && !req->ad)
    msg->flags &= ~HSK_DNS_AD;

  // Finalize and sign if key is available.
  if (!hsk_dns_msg_finalize(&msg, req, ns->ec, ns->key, &wire, &wire_len)) {
    hsk_rs_log(ns, "could not finalize msg\n");
    goto fail;
  }

  goto done;

fail:
  assert(!msg);

  msg = hsk_resource_to_servfail();

  if (!msg) {
    hsk_rs_log(ns, "could not create servfail\n");
    return;
  }

  if (!hsk_dns_msg_finalize(&msg, req, ns->ec, ns->key, &wire, &wire_len)) {
    hsk_rs_log(ns, "could not finalize msg\n");
    return;
  }

done:
  hsk_rs_send(ns, wire, wire_len, req->addr, true);
}

static int
hsk_rs_send(
  hsk_rs_t *ns,
  uint8_t *data,
  size_t data_len,
  const struct sockaddr *addr,
  bool should_free
) {
  int rc = HSK_SUCCESS;
  hsk_send_data_t *sd = NULL;
  uv_udp_send_t *req = NULL;

  if (!ns->socket) {
    rc = HSK_EFAILURE;
    goto fail;
  }

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
    { .base = (char *)data, .len = data_len }
  };

  int status = uv_udp_send(req, ns->socket, bufs, 1, addr, after_send);

  if (status != 0) {
    hsk_rs_log(ns, "failed sending: %s\n", uv_strerror(status));
    rc = HSK_EFAILURE;
    goto fail;
  }

  return rc;

fail:
  if (sd)
    free(sd);

  if (req)
    free(req);

  if (data && should_free)
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
after_worker_stop(void *data) {
  hsk_rs_t *ns = (hsk_rs_t *)data;

  if (ns->rs_worker) {
    hsk_rs_worker_free(ns->rs_worker);
    ns->rs_worker = NULL;
  }

  if (ns->receiving) {
    uv_udp_recv_stop(ns->socket);
    ns->receiving = false;
  }

  if (ns->socket) {
    hsk_uv_close_free((uv_handle_t *)ns->socket);
    ns->socket->data = NULL;
    ns->socket = NULL;
  }

  if (ns->ub) {
    ub_ctx_delete(ns->ub);
    ns->ub = NULL;
  }

  // Grab these values, ns may be freed by this callback.
  void *stop_data = ns->stop_data;
  void (*stop_callback)(void *) = ns->stop_callback;
  ns->stop_callback = NULL;

  stop_callback(stop_data);
}

static void
after_send(uv_udp_send_t *req, int status) {
  hsk_send_data_t *sd = (hsk_send_data_t *)req->data;
  hsk_rs_t *ns = sd->ns;

  if (sd->data && sd->should_free)
    free(sd->data);

  free(sd);
  free(req);

  if (!ns)
    return;

  if (status != 0) {
    hsk_rs_log(ns, "send error: %s\n", uv_strerror(status));
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
  // Happens after every msg?
  if (nread == 0 && addr == NULL)
    return;

  // Never seems to happen on its own.
  if (addr == NULL)
    return;

  hsk_rs_onrecv(
    ns,
    (uint8_t *)buf->base,
    (size_t)nread,
    (struct sockaddr *)addr,
    (uint32_t)flags
  );
}

static void
after_resolve(void *data, int status, struct ub_result *result) {
  hsk_dns_req_t *req = (hsk_dns_req_t *)data;
  hsk_rs_t *ns = (hsk_rs_t *)req->ns;

  assert(ns);

  // If the request is aborted, result is NULL, we just need to free req in that
  // case
  if (result) {
    hsk_rs_respond(ns, req, status, result);
    ub_resolve_free(result);
  }
  hsk_dns_req_free(req);
}
