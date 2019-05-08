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
after_send(uv_udp_send_t *req, int status);

static void
after_recv(
  uv_udp_t *socket,
  ssize_t nread,
  const uv_buf_t *buf,
  const struct sockaddr *addr,
  unsigned flags
);

// Resolve callback on libunbound worker thread.
static void
after_resolve_onthread(void *data, int status, struct ub_result *result);

// Resolve async event handler in libuv event loop.
static void
after_resolve(uv_async_t *async);

static void
after_close(uv_handle_t *handle);

static void
after_close_free(uv_handle_t *handle);

static void
run_unbound_worker(void *arg);

static void
after_resolve_shutdown(void *data, int status, struct ub_result *result);

/*
 * Response Queue
 */
int
hsk_rs_queue_init(hsk_rs_queue_t *queue) {
  if (uv_mutex_init(&queue->mutex))
    return HSK_EFAILURE;
  queue->head = NULL;
  queue->tail = NULL;

  return HSK_SUCCESS;
}

void
hsk_rs_queue_uninit(hsk_rs_queue_t *queue) {
  hsk_rs_rsp_t *current = queue->head;
  while (current) {
    hsk_rs_rsp_t *next = current->next;
    free(current);
    current = next;
  }

  uv_mutex_destroy(&queue->mutex);
}

hsk_rs_queue_t *hsk_rs_queue_alloc() {
  hsk_rs_queue_t *queue = malloc(sizeof(hsk_rs_queue_t));
  if(!queue)
    return NULL;

  if (hsk_rs_queue_init(queue) != HSK_SUCCESS) {
    free(queue);
    return NULL;
  }

  return queue;
}

void hsk_rs_queue_free(hsk_rs_queue_t *queue) {
  if(!queue)
    return;

  hsk_rs_queue_uninit(queue);
  free(queue);
}

// Dequeue the oldest queued response - thread-safe.
// Returned object is now owned by the caller; returns nullptr if there is
// nothing queued.
hsk_rs_rsp_t *
hsk_rs_queue_dequeue(hsk_rs_queue_t *queue) {
  uv_mutex_lock(&queue->mutex);

  hsk_rs_rsp_t *oldest = queue->head;
  if (oldest) {
    queue->head = oldest->next;
    oldest->next = NULL;
    // If this was the only queued request, clear tail too
    if(queue->tail == oldest)
      queue->tail = NULL;
  }

  uv_mutex_unlock(&queue->mutex);

  return oldest;
}

// Enqueue a response - thread-safe.
// The queue takes ownership of the response (until it's popped off again).
void
hsk_rs_queue_enqueue(hsk_rs_queue_t *queue, hsk_rs_rsp_t *rsp) {
  uv_mutex_lock(&queue->mutex);

  if (!queue->tail) {
    // There were no requests queued; this one becomes head and tail
    assert(!queue->head);   // Invariant - set and cleared together
    queue->head = rsp;
    queue->tail = rsp;
  }
  else {
    // There are requests queued already, add this one to the tail
    queue->tail->next = rsp;
    queue->tail = rsp;
  }

  uv_mutex_unlock(&queue->mutex);
}

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
  hsk_rs_queue_t *rs_queue = NULL;
  uv_async_t *rs_async = NULL;

  ub = ub_ctx_create();

  if (!ub)
    goto fail;

  if (ub_ctx_async(ub, 1) != 0)
    goto fail;

  rs_queue = hsk_rs_queue_alloc();

  if (!rs_queue)
    goto fail;

  // Allocate this separately on the heap because uv_close() is asynchronous.
  rs_async = malloc(sizeof(uv_async_t));
  if (!rs_async || uv_async_init((uv_loop_t*)loop, rs_async, after_resolve))
    goto fail;

  ec = hsk_ec_alloc();

  if (!ec)
    goto fail;

  ns->loop = (uv_loop_t *)loop;
  ns->ub = ub;
  ns->socket.data = (void *)ns;
  ns->rs_queue = rs_queue;
  ns->rs_async = rs_async;
  ns->rs_async->data = (void *)ns;
  ns->ec = ec;
  ns->config = NULL;
  ns->stub = (struct sockaddr *)&ns->stub_;
  assert(hsk_sa_from_string(ns->stub, "127.0.0.1", HSK_NS_PORT));
  memset(ns->key_, 0x00, sizeof(ns->key_));
  ns->key = NULL;
  memset(ns->pubkey, 0x00, sizeof(ns->pubkey));
  memset(ns->read_buffer, 0x00, sizeof(ns->read_buffer));
  ns->bound = false;
  ns->receiving = false;
  ns->rs_worker_running = false;

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

  if (rs_queue)
    hsk_rs_queue_free(rs_queue);

  if (rs_async)
    free(rs_async);

  if (ec)
    hsk_ec_free(ec);

  return err;
}

void
hsk_rs_uninit(hsk_rs_t *ns) {
  if (!ns)
    return;

  ns->socket.data = NULL;

  if (ns->ec) {
    hsk_ec_free(ns->ec);
    ns->ec = NULL;
  }

  if (ns->ub) {
    ub_ctx_delete(ns->ub);
    ns->ub = NULL;
  }

  // Free the response event and queue after destroying the unbound context.
  // The libunbound worker has now stopped, so we can safely free these.
  if (ns->rs_async) {
    ns->rs_async->data = NULL;
    // We have to free this object in the callback, libuv specifically says it
    // must not be freed before the callback occurs
    uv_close((uv_handle_t *)ns->rs_async, after_close_free);
    ns->rs_async = NULL;
  }

  if (ns->rs_queue) {
    hsk_rs_queue_free(ns->rs_queue);
    ns->rs_queue = NULL;
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

  if (uv_udp_init(ns->loop, &ns->socket) != 0)
    return HSK_EFAILURE;

  ns->socket.data = (void *)ns;

  if (uv_udp_bind(&ns->socket, addr, 0) != 0)
    return HSK_EFAILURE;

  ns->bound = true;

  int value = sizeof(ns->read_buffer);

  if (uv_send_buffer_size((uv_handle_t *)&ns->socket, &value) != 0)
    return HSK_EFAILURE;

  if (uv_recv_buffer_size((uv_handle_t *)&ns->socket, &value) != 0)
    return HSK_EFAILURE;

  if (uv_udp_recv_start(&ns->socket, alloc_buffer, after_recv) != 0)
    return HSK_EFAILURE;

  ns->receiving = true;

  ns->rs_worker_running = true;
  if (uv_thread_create(&ns->rs_worker, run_unbound_worker, (void *)ns) != 0) {
    ns->rs_worker_running = false;
    return HSK_EFAILURE;
  }

  char host[HSK_MAX_HOST];
  assert(hsk_sa_to_string(addr, host, HSK_MAX_HOST, HSK_NS_PORT));

  hsk_rs_log(ns, "recursive nameserver listening on: %s\n", host);

  return HSK_SUCCESS;
}

int
hsk_rs_close(hsk_rs_t *ns) {
  if (!ns)
    return HSK_EBADARGS;

  if (ns->rs_worker_running) {
    // We need to tell the libunbound worker to exit - wake up the thread and
    // clear rs_worker_running on that thread.
    //
    // libunbound doesn't give us a good way to do this, the only way is to
    // issue a dummy query and do this in the callback on the worker thread.
    //
    // On Unix, we could poll unbound's file descriptor manually with another
    // file descriptor to allow us to wake the thread here.  On Windows though,
    // libunbound does not provide any access to its WSAEVENT to do the same
    // thing.
    int rc = ub_resolve_async(ns->ub, ".", HSK_DNS_NS, HSK_DNS_IN, (void *)ns,
                              after_resolve_shutdown, NULL);
    if(rc != 0)
      hsk_rs_log(ns, "cannot shut down worker thread: %s\n", ub_strerror(rc));
    else
      uv_thread_join(&ns->rs_worker);
  }

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

  if (ns->ub) {
    ub_ctx_delete(ns->ub);
    ns->ub = NULL;
  }

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

int
hsk_rs_destroy(hsk_rs_t *ns) {
  if (!ns)
    return HSK_EBADARGS;

  int rc = hsk_rs_close(ns);

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

  rc = ub_resolve_async(
    ns->ub,
    req->name,
    req->type,
    req->class,
    (void *)req,
    after_resolve_onthread,
    NULL
  );

  if (rc == 0)
    return;

  hsk_rs_log(ns, "unbound error: %s\n", ub_strerror(rc));

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

  hsk_rs_log(ns, "received answer for: %s\n", req->name);

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

  int status = uv_udp_send(req, &ns->socket, bufs, 1, addr, after_send);

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

// Handle a resolve result and respond to a DNS query for the recursive
// resolver - called on the libunbound worker thread
static void
after_resolve_onthread(void *data, int status, struct ub_result *result) {
  hsk_dns_req_t *req = (hsk_dns_req_t *)data;
  // We can safely get the nameserver object from the request; the main thread
  // does not use it after ub_resolve_async() succeeds (ownership is passed to
  // this callback).
  hsk_rs_t *ns = (hsk_rs_t *)req->ns;

  hsk_rs_rsp_t *rsp = malloc(sizeof(hsk_rs_rsp_t));
  if(!rsp)
    return;

  rsp->next = NULL;
  rsp->req = req;
  rsp->result = result;
  rsp->status = status;

  // Enqueue the response.  This is safe to do on the worker thread:
  // - The ns->rs_queue pointer is not modified after initialization until the
  //   worker thread has been stopped
  // - The hsk_rs_queue_t object itself is thread-safe
  hsk_rs_queue_enqueue(ns->rs_queue, rsp);

  // Queue an async event to process the response on the libuv event loop.
  // Like rs_queue, the rs_async pointer is safe to use because it's not
  // modified until the libunbound worker is stopped.
  uv_async_send(ns->rs_async);
}

static void
after_resolve(uv_async_t *async) {
  hsk_rs_t *ns = (hsk_rs_t *)async->data;

  // Since uv_close() is async, it might be possible to process this event after
  // the NS is shut down but before the async is closed.
  if(!ns)
    return;

  // Dequeue and process all events in the queue - libuv coalesces calls to
  // uv_async_send().
  hsk_rs_rsp_t *rsp = hsk_rs_queue_dequeue(ns->rs_queue);
  while(rsp) {
    hsk_rs_respond(ns, rsp->req, rsp->status, rsp->result);

    hsk_dns_req_free(rsp->req);
    ub_resolve_free(rsp->result);
    free(rsp);

    rsp = hsk_rs_queue_dequeue(ns->rs_queue);
  }
}

static void
after_close(uv_handle_t *handle) {}

static void
after_close_free(uv_handle_t *handle) {
  free(handle);
}

static void
run_unbound_worker(void *arg) {
  hsk_rs_t *ns = (hsk_rs_t *)arg;

  while(ns->rs_worker_running) {
    ub_wait(ns->ub);
  }
}

static void
after_resolve_shutdown(void *data, int status, struct ub_result *result) {
  ub_resolve_free(result);

  hsk_rs_t *ns = (hsk_rs_t *)data;

  ns->rs_worker_running = false;
}
