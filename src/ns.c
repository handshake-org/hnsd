#include "config.h"

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


#include "addr.h"
#include "constants.h"
#include "dns.h"
#include "ec.h"
#include "error.h"
#include "resource.h"
#include "ns.h"
#include "pool.h"
#include "req.h"
#include "sig0.h"
#include "uv.h"

/*
 * Types
 */

typedef struct {
  hsk_ns_t *ns;
  void *data;
  bool should_free;
} hsk_send_data_t;

/*
 * Templates
 */

static void
hsk_ns_log(hsk_ns_t *, const char *, ...);

static void
after_resolve(
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
  hsk_addr_init(&ns->ip_);
  ns->ip = NULL;
  ns->socket.data = (void *)ns;
  ns->ec = ec;
  memset(ns->key_, 0x00, sizeof(ns->key_));
  ns->key = NULL;
  memset(ns->pubkey, 0x00, sizeof(ns->pubkey));
  memset(ns->read_buffer, 0x00, sizeof(ns->read_buffer));
  ns->bound = false;
  ns->receiving = false;

  return HSK_SUCCESS;
}

void
hsk_ns_uninit(hsk_ns_t *ns) {
  if (!ns)
    return;

  ns->socket.data = NULL;

  if (ns->ec) {
    hsk_ec_free(ns->ec);
    ns->ec = NULL;
  }
}

bool
hsk_ns_set_ip(hsk_ns_t *ns, struct sockaddr *addr) {
  assert(ns);

  if (!addr) {
    hsk_addr_init(&ns->ip_);
    ns->ip = NULL;
    return true;
  }

  if (!hsk_addr_from_sa(&ns->ip_, addr))
    return false;

  if (!hsk_addr_localize(&ns->ip_))
    return false;

  ns->ip = &ns->ip_;

  return true;
}

bool
hsk_ns_set_key(hsk_ns_t *ns, uint8_t *key) {
  assert(ns);

  if (!key) {
    memset(ns->key_, 0x00, 32);
    ns->key = NULL;
    memset(ns->pubkey, 0x00, sizeof(ns->pubkey));
    return true;
  }

  if (!hsk_ec_create_pubkey(ns->ec, key, ns->pubkey))
    return false;

  memcpy(ns->key_, key, 32);
  ns->key = ns->key_;

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
  hsk_dns_req_t *req = hsk_dns_req_create(data, data_len, addr);

  if (!req) {
    hsk_ns_log(ns, "failed processing dns request\n");
    return;
  }

  hsk_dns_req_print(req, "ns: ");

  bool result;
  uint8_t *wire;
  size_t wire_len;

  // Requesting a lookup.
  if (req->labels > 0) {
    req->ns = (void *)ns;

    int32_t rc = hsk_pool_resolve(
      ns->pool,
      req->tld,
      after_resolve,
      (void *)req
    );

    if (rc != HSK_SUCCESS) {
      hsk_ns_log(ns, "pool resolve error: %d\n", rc);
      goto fail;
    }

    return;
  }

  // Querying the root zone.
  result = hsk_resource_root(
    req->id,
    req->type,
    req->edns,
    req->dnssec,
    ns->ip,
    &wire,
    &wire_len
  );

  if (!result) {
    hsk_ns_log(ns, "could not create root soa\n");
    goto fail;
  }

  if (ns->key) {
    if (!hsk_sig0_sign_msg(ns->ec, ns->key, &wire, &wire_len)) {
      hsk_ns_log(ns, "could not sign response\n");
      goto fail;
    }
  }

  hsk_ns_log(ns, "sending root soa (%d): %d\n", req->id, wire_len);

  hsk_ns_send(ns, wire, wire_len, addr, true);

  goto done;

fail:
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
    hsk_ns_log(ns, "failed creating servfail\n");
    goto done;
  }

  hsk_ns_log(ns, "sending servfail (%d): %d\n", req->id, wire_len);

  hsk_ns_send(ns, wire, wire_len, addr, true);

done:
  if (req)
    hsk_dns_req_free(req);
}

static void
hsk_ns_respond(
  hsk_ns_t *ns,
  hsk_dns_req_t *req,
  int32_t status,
  hsk_resource_t *res
) {
  bool result;
  uint8_t *wire;
  size_t wire_len;

  if (status != HSK_SUCCESS) {
    // Pool resolve error.
    result = false;
    hsk_ns_log(ns, "resolve response error: %d\n", status);
  } else if (!res) {
    // Doesn't exist.
    result = hsk_resource_to_nx(
      req->id,
      req->name,
      req->type,
      req->edns,
      req->dnssec,
      &wire,
      &wire_len
    );

    if (!result)
      hsk_ns_log(ns, "could not create nx response\n");
    else
      hsk_ns_log(ns, "sending nxdomain (%d): %d\n", req->id, wire_len);
  } else {
    // Exists!
    result = hsk_resource_to_dns(
      res,
      req->id,
      req->name,
      req->type,
      req->edns,
      req->dnssec,
      &wire,
      &wire_len
    );

    if (!result)
      hsk_ns_log(ns, "could not create dns response\n");
    else
      hsk_ns_log(ns, "sending msg (%d): %d\n", req->id, wire_len);
  }

  if (result && ns->key) {
    if (!hsk_sig0_sign_msg(ns->ec, ns->key, &wire, &wire_len)) {
      hsk_ns_log(ns, "could not sign response\n");
      result = false;
    }
  }

  if (!result) {
    // Send SERVFAIL in case of error.
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
      hsk_ns_log(ns, "could not create servfail response\n");
      return;
    }

    hsk_ns_log(ns, "sending servfail (%d): %d\n", req->id, wire_len);
  }

  hsk_ns_send(ns, wire, wire_len, req->addr, true);
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

  if (data && should_free)
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

  if (sd->data && sd->should_free)
    free(sd->data);

  free(sd);
  free(req);

  if (!ns)
    return;

  if (status != 0) {
    hsk_ns_log(ns, "send error: %s\n", uv_strerror(status));
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
    hsk_ns_log(ns, "udp read error: %s\n", uv_strerror(nread));
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

static void
after_resolve(
  char *name,
  int32_t status,
  bool exists,
  uint8_t *data,
  size_t data_len,
  void *arg
) {
  hsk_dns_req_t *req = (hsk_dns_req_t *)arg;
  hsk_ns_t *ns = (hsk_ns_t *)req->ns;
  hsk_resource_t *res = NULL;

  if (status == HSK_SUCCESS && exists) {
    if (!hsk_resource_decode(data, data_len, &res)) {
      hsk_ns_log(ns, "could not decode resource for: %s\n", name);
      status = HSK_EFAILURE;
      res = NULL;
    }
  }

  hsk_ns_respond(ns, req, status, res);

  if (res)
    hsk_resource_free(res);

  hsk_dns_req_free(req);
}
