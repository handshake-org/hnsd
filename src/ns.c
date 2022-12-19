#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "addr.h"
#include "cache.h"
#include "constants.h"
#include "dns.h"
#include "ec.h"
#include "error.h"
#include "resource.h"
#include "ns.h"
#include "pool.h"
#include "req.h"
#include "tld.h"
#include "platform-net.h"
#include "utils.h"
#include "uv.h"
#include "dnssec.h"
#include "hesiod.h"

// A RRSIG NSEC
static const uint8_t hsk_type_map_a[] = {
  0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x03
};

// AAAA RRSIG NSEC
static const uint8_t hsk_type_map_aaaa[] = {
  0x00, 0x06, 0x00, 0x00, 0x00, 0x80, 0x00, 0x03
};

/*
 * Types
 */

typedef struct {
  hsk_ns_t *ns;
  void *data;
  bool should_free;
} hsk_send_data_t;

/*
 * Prototypes
 */

static void
hsk_ns_log(hsk_ns_t *ns, const char *fmt, ...);

static void
after_resolve(
  const char *name,
  int status,
  bool exists,
  const uint8_t *data,
  size_t data_len,
  const void *arg
);

int
hsk_ns_send(
  hsk_ns_t *ns,
  uint8_t *data,
  size_t data_len,
  const struct sockaddr *addr,
  bool should_free
);

static void
alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf);

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
after_close(uv_handle_t *handle);

static int
hsk_tld_index(const char *name);

static const uint8_t *
hsk_icann_lookup(const char *name);

/*
 * Root Nameserver
 */

int
hsk_ns_init(hsk_ns_t *ns, const uv_loop_t *loop, const hsk_pool_t *pool) {
  if (!ns || !loop || !pool)
    return HSK_EBADARGS;

  hsk_ec_t *ec = hsk_ec_alloc();

  if (!ec)
    return HSK_ENOMEM;

  ns->loop = (uv_loop_t *)loop;
  ns->pool = (hsk_pool_t *)pool;
  hsk_addr_init(&ns->ip_);
  ns->ip = NULL;
  ns->socket = NULL;
  ns->ec = ec;
  hsk_cache_init(&ns->cache);
  memset(ns->key_, 0x00, sizeof(ns->key_));
  ns->key = NULL;
  memset(ns->pubkey, 0x00, sizeof(ns->pubkey));
  memset(ns->read_buffer, 0x00, sizeof(ns->read_buffer));
  ns->receiving = false;

  return HSK_SUCCESS;
}

void
hsk_ns_uninit(hsk_ns_t *ns) {
  if (!ns)
    return;

  if (ns->ec) {
    hsk_ec_free(ns->ec);
    ns->ec = NULL;
  }

  hsk_cache_uninit(&ns->cache);
}

bool
hsk_ns_set_ip(hsk_ns_t *ns, const struct sockaddr *addr) {
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
hsk_ns_set_key(hsk_ns_t *ns, const uint8_t *key) {
  assert(ns);

  if (!key) {
    memset(ns->key_, 0x00, 32);
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

int
hsk_ns_open(hsk_ns_t *ns, const struct sockaddr *addr) {
  if (!ns || !addr)
    return HSK_EBADARGS;

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

  if (!ns->ip)
    hsk_ns_set_ip(ns, addr);

  char host[HSK_MAX_HOST];
  assert(hsk_sa_to_string(addr, host, HSK_MAX_HOST, HSK_NS_PORT));

  hsk_ns_log(ns, "root nameserver listening on: %s\n", host);

  return HSK_SUCCESS;
}

int
hsk_ns_close(hsk_ns_t *ns) {
  if (!ns)
    return HSK_EBADARGS;

  if (ns->receiving) {
    if (uv_udp_recv_stop(ns->socket) != 0)
      return HSK_EFAILURE;
    ns->receiving = false;
  }

  if (ns->socket) {
    hsk_uv_close_free((uv_handle_t *)ns->socket);
    ns->socket->data = NULL;
    ns->socket = NULL;
  }

  return HSK_SUCCESS;
}

hsk_ns_t *
hsk_ns_alloc(const uv_loop_t *loop, const hsk_pool_t *pool) {
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

int
hsk_ns_destroy(hsk_ns_t *ns) {
  if (!ns)
    return HSK_EBADARGS;

  int rc = hsk_ns_close(ns);

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
  const uint8_t *data,
  size_t data_len,
  const struct sockaddr *addr,
  uint32_t flags
) {
  hsk_dns_req_t *req = hsk_dns_req_create(data, data_len, addr);

  if (!req) {
    hsk_ns_log(ns, "failed processing dns request\n");
    return;
  }

  hsk_dns_req_print(req, "ns: ");

  uint8_t *wire = NULL;
  size_t wire_len = 0;
  hsk_dns_msg_t *msg = NULL;

  // Hit cache first.
  msg = hsk_cache_get(&ns->cache, req);

  if (msg) {
    if (!hsk_dns_msg_finalize(&msg, req, ns->ec, ns->key, &wire, &wire_len)) {
      hsk_ns_log(ns, "could not reply\n");
      goto fail;
    }

    hsk_ns_log(ns, "sending cached msg (%u): %u\n", req->id, wire_len);

    hsk_ns_send(ns, wire, wire_len, addr, true);

    goto done;
  }

  bool should_cache = true;
  // Hesiod class is used for local text queries of internal metadata
  if (req->class == HSK_DNS_HS
    && req->type == HSK_DNS_TXT
  ) {
    should_cache = false;

    hsk_addr_t address;
    hsk_addr_from_sa(&address, req->addr);
    if (!hsk_addr_is_local(&address)) {
      hsk_ns_log(ns, "ignoring non-local HS class request\n");
      goto done;
    }

    msg = hsk_hesiod_resolve(req, ns);
    if (!msg) {
      hsk_ns_log(ns, "unknown HS class request\n");
      goto fail;
    }

    if (!hsk_dns_msg_finalize(&msg, req, ns->ec, ns->key, &wire, &wire_len)) {
      hsk_ns_log(ns, "could not reply to HS class request\n");
      goto fail;
    }

    hsk_ns_send(ns, wire, wire_len, addr, true);

    goto done;
  }

  // Handle reverse pointers.
  // See https://github.com/handshake-org/hsd/issues/125
  // Resolving a name with a synth record will return an NS record
  // with a name that encodes an IP address: _[base32]._synth.
  // The synth name then resolves to an A/AAAA record that is derived
  // by decoding the name itself (it does not have to be looked up).
  if (strcmp(req->tld, "_synth") == 0 && req->labels <= 2) {
    msg = hsk_dns_msg_alloc();
    should_cache = false;

    if (!msg)
      goto fail;

    hsk_dns_rrs_t *an = &msg->an;
    hsk_dns_rrs_t *rrns = &msg->ns;
    hsk_dns_rrs_t *ar = &msg->ar;

    // TLD '._synth' is being queried on its own, send SOA
    // so recursive asks again with complete synth record.
    if (req->labels == 1) {
      hsk_resource_to_empty(req->tld, NULL, 0, rrns);
      hsk_dnssec_sign_zsk(rrns, HSK_DNS_NSEC);
      hsk_resource_root_to_soa(rrns);
      hsk_dnssec_sign_zsk(rrns, HSK_DNS_SOA);

      goto finalize;
    }

    uint8_t ip[16];
    uint16_t family;
    char synth[HSK_DNS_MAX_LABEL + 1];
    // Will buffer overflow if req->name doesn't
    // have at least 2 labels.
    hsk_dns_label_from(req->name, -2, synth);

    if (pointer_to_ip(synth, ip, &family)) {
      bool match = false;

      switch (req->type) {
        case HSK_DNS_ANY:
          match = true;
          break;
        case HSK_DNS_A:
          match = family == HSK_DNS_A;
          break;
        case HSK_DNS_AAAA:
          match = family == HSK_DNS_AAAA;
          break;
      }

      if (!match) {
        // Needs SOA.
        // TODO: Make the reverse pointers TLDs.
        // Empty proof:
        if (family == HSK_DNS_A) {
          hsk_resource_to_empty(
            req->name,
            hsk_type_map_a,
            sizeof(hsk_type_map_a),
            rrns
          );
        } else {
          hsk_resource_to_empty(
            req->name,
            hsk_type_map_aaaa,
            sizeof(hsk_type_map_aaaa),
            rrns
          );
        }
        hsk_dnssec_sign_zsk(rrns, HSK_DNS_NSEC);
        hsk_resource_root_to_soa(rrns);
        hsk_dnssec_sign_zsk(rrns, HSK_DNS_SOA);
      } else {
        uint16_t rrtype = family;

        msg->flags |= HSK_DNS_AA;

        hsk_dns_rr_t *rr = hsk_dns_rr_create(rrtype);

        if (!rr) {
          hsk_dns_msg_free(msg);
          goto fail;
        }

        rr->ttl = HSK_DEFAULT_TTL;
        hsk_dns_rr_set_name(rr, req->name);

        if (family == HSK_DNS_A) {
          hsk_dns_a_rd_t *rd = rr->rd;
          memcpy(&rd->addr[0], &ip[0], 4);
        } else {
          hsk_dns_aaaa_rd_t *rd = rr->rd;
          memcpy(&rd->addr[0], &ip[0], 16);
        }

        hsk_dns_rrs_push(an, rr);

        hsk_dnssec_sign_zsk(ar, rrtype);
      }
    }

finalize:

    if (!hsk_dns_msg_finalize(&msg, req, ns->ec, ns->key, &wire, &wire_len)) {
      hsk_ns_log(ns, "could not reply\n");
      goto fail;
    }

    hsk_ns_log(ns, "sending synthesized msg (%u): %u\n", req->id, wire_len);

    hsk_ns_send(ns, wire, wire_len, addr, true);

    goto done;
  }

  // Requesting a lookup.
  if (req->labels > 0) {
    // Check blacklist.
    if (strcmp(req->tld, "bit") == 0 // Namecoin
        || strcmp(req->tld, "eth") == 0 // ENS
        || strcmp(req->tld, "exit") == 0 // Tor
        || strcmp(req->tld, "gnu") == 0 // GNUnet (GNS)
        || strcmp(req->tld, "i2p") == 0 // Invisible Internet Project
        || strcmp(req->tld, "onion") == 0 // Tor
        || strcmp(req->tld, "tor") == 0 // OnioNS
        || strcmp(req->tld, "zkey") == 0) { // GNS
      msg = hsk_resource_to_nx();
    } else {
      req->ns = (void *)ns;

      int rc = hsk_pool_resolve(
        ns->pool,
        req->tld,
        after_resolve,
        (void *)req
      );

      if (rc != HSK_SUCCESS) {
        hsk_ns_log(ns, "pool resolve error: %s\n", hsk_strerror(rc));
        goto fail;
      }

      return;
    }
  } else {
    // Querying the root zone.
    msg = hsk_resource_root(req->type, ns->ip);
  }

  if (!msg) {
    hsk_ns_log(ns, "could not create root soa\n");
    goto fail;
  }

  if (should_cache)
    hsk_cache_insert(&ns->cache, req, msg);

  if (!hsk_dns_msg_finalize(&msg, req, ns->ec, ns->key, &wire, &wire_len)) {
    hsk_ns_log(ns, "could not reply\n");
    goto fail;
  }

  hsk_ns_send(ns, wire, wire_len, addr, true);

  goto done;

fail:
  assert(!msg);

  msg = hsk_resource_to_servfail();

  if (!msg) {
    hsk_ns_log(ns, "failed creating servfail\n");
    goto done;
  }

  if (!hsk_dns_msg_finalize(&msg, req, ns->ec, ns->key, &wire, &wire_len)) {
    hsk_ns_log(ns, "could not reply\n");
    goto done;
  }

  hsk_ns_log(ns, "sending servfail (%u): %u\n", req->id, wire_len);

  hsk_ns_send(ns, wire, wire_len, addr, true);

done:
  if (req)
    hsk_dns_req_free(req);
}

static void
hsk_ns_respond(
  hsk_ns_t *ns,
  const hsk_dns_req_t *req,
  int status,
  const hsk_resource_t *res
) {
  hsk_dns_msg_t *msg = NULL;
  uint8_t *wire = NULL;
  size_t wire_len = 0;

  if (status != HSK_SUCCESS) {
    // Pool resolve error.
    hsk_ns_log(ns, "resolve response error: %s\n", hsk_strerror(status));
  } else if (!res) {
    // Doesn't exist.
    //
    // We should be giving a real NSEC proof
    // here, but I don't think it's possible
    // with the current construction.
    //
    // I imagine this would only be possible
    // if NSEC3 begins to support BLAKE2b for
    // name hashing. Even then, it's still
    // not possible for SPV nodes since they
    // can't arbitrarily iterate over the tree.
    //
    // Instead, we give a phony proof, which
    // makes the root zone look empty.
    msg = hsk_resource_to_nx();

    if (!msg)
      hsk_ns_log(ns, "could not create nx response (%u)\n", req->id);
    else
      hsk_ns_log(ns, "sending nxdomain (%u)\n", req->id);
  } else {
    // Exists!
    msg = hsk_resource_to_dns(res, req->name, req->type);

    if (!msg)
      hsk_ns_log(ns, "could not create dns response (%u)\n", req->id);
    else
      hsk_ns_log(ns, "sending msg (%u)\n", req->id);
  }

  if (msg) {
    hsk_cache_insert(&ns->cache, req, msg);

    if (!hsk_dns_msg_finalize(&msg, req, ns->ec, ns->key, &wire, &wire_len)) {
      assert(!msg && !wire);
      hsk_ns_log(ns, "could not finalize\n");
    }
  }

  if (!wire) {
    // Send SERVFAIL in case of error.
    assert(!msg);

    msg = hsk_resource_to_servfail();

    if (!msg) {
      hsk_ns_log(ns, "could not create servfail response\n");
      return;
    }

    if (!hsk_dns_msg_finalize(&msg, req, ns->ec, ns->key, &wire, &wire_len)) {
      hsk_ns_log(ns, "could not create servfail\n");
      return;
    }

    hsk_ns_log(ns, "sending servfail (%u): %u\n", req->id, wire_len);
  }

  hsk_ns_send(ns, wire, wire_len, req->addr, true);
}

int
hsk_ns_send(
  hsk_ns_t *ns,
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
    hsk_ns_log(ns, "failed sending: %s\n", uv_strerror(status));
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
  // Happens after every msg?
  if (nread == 0 && addr == NULL)
    return;

  // Never seems to happen on its own.
  if (addr == NULL)
    return;

  hsk_ns_onrecv(
    ns,
    (uint8_t *)buf->base,
    (size_t)nread,
    (struct sockaddr *)addr,
    (uint32_t)flags
  );
}

static void
after_resolve(
  const char *name,
  int status,
  bool exists,
  const uint8_t *data,
  size_t data_len,
  const void *arg
) {
  hsk_dns_req_t *req = (hsk_dns_req_t *)arg;
  hsk_ns_t *ns = (hsk_ns_t *)req->ns;
  hsk_resource_t *res = NULL;

  if (status == HSK_SUCCESS) {
    if (!exists || data_len == 0) {
      const uint8_t *item = hsk_icann_lookup(name);

      if (item) {
        const uint8_t *raw = &item[2];
        size_t raw_len = (((size_t)item[1]) << 8) | ((size_t)item[0]);

        if (!hsk_resource_decode(raw, raw_len, &res)) {
          hsk_ns_log(ns, "could not decode root resource for: %s\n", name);
          status = HSK_EFAILURE;
          res = NULL;
        }
      }
    } else {
      if (!hsk_resource_decode(data, data_len, &res)) {
        hsk_ns_log(ns, "could not decode resource for: %s\n", name);
        status = HSK_EFAILURE;
        res = NULL;
      }
    }
  }

  hsk_ns_respond(ns, req, status, res);

  if (res)
    hsk_resource_free(res);

  hsk_dns_req_free(req);
}

static int
hsk_tld_index(const char *name) {
  int start = 0;
  int end = HSK_TLD_SIZE - 1;

  while (start <= end) {
    int pos = (start + end) >> 1;
    int cmp = strcasecmp(HSK_TLD_NAMES[pos], name);

    if (cmp == 0)
      return pos;

    if (cmp < 0)
      start = pos + 1;
    else
      end = pos - 1;
  }

  return -1;
}

static const uint8_t *
hsk_icann_lookup(const char *name) {
  int index = hsk_tld_index(name);

  if (index == -1)
    return NULL;

  return (const uint8_t *)HSK_TLD_DATA[index];
}
