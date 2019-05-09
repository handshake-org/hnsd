#include "config.h"

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <unbound.h>

#include "dns.h"
#include "error.h"
#include "rs_worker.h"
#include "utils.h"
#include "uv.h"

/*
 * Prototypes
 */
static void
hsk_rs_worker_log(hsk_rs_worker_t *ns, const char *fmt, ...);

static uv_async_t *
alloc_async(hsk_rs_worker_t *worker, uv_loop_t *loop, uv_async_cb callback);

static void
free_async(uv_async_t *async);

static void
run_unbound_worker(void *arg);

static void
after_resolve_shutdown(void *data, int status, struct ub_result *result);

static void
after_resolve_onthread(void *data, int status, struct ub_result *result);

static void
after_resolve_async(uv_async_t *async);

static void
after_quit_async(uv_async_t *async);

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

hsk_rs_queue_t *
hsk_rs_queue_alloc() {
  hsk_rs_queue_t *queue = malloc(sizeof(hsk_rs_queue_t));
  if (!queue)
    return NULL;

  if (hsk_rs_queue_init(queue) != HSK_SUCCESS) {
    free(queue);
    return NULL;
  }

  return queue;
}

void
hsk_rs_queue_free(hsk_rs_queue_t *queue) {
  if(queue) {
    hsk_rs_queue_uninit(queue);
    free(queue);
  }
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
 * Response worker thread
 */
int
hsk_rs_worker_init(hsk_rs_worker_t *worker, uv_loop_t *loop, void *stop_data,
                   void (*stop_callback)(void *)) {
  if (!worker || !loop || !stop_callback)
    return HSK_EBADARGS;

  worker->rs_queue = NULL;
  worker->rs_async = NULL;
  worker->ub = NULL;
  worker->cb_stop_data = stop_data;
  worker->cb_stop_func = stop_callback;
  worker->closing = false;

  worker->rs_queue = hsk_rs_queue_alloc();
  if (!worker->rs_queue) {
    hsk_rs_worker_log(worker, "failed to create response queue");
    goto fail;
  }

  worker->rs_async = alloc_async(worker, loop, after_resolve_async);
  if (!worker->rs_async)
    goto fail;

  worker->rs_quit_async = alloc_async(worker, loop, after_quit_async);
  if (!worker->rs_quit_async)
    goto fail;

  return HSK_SUCCESS;

fail:
  hsk_rs_worker_uninit(worker);

  return HSK_EFAILURE;
}

void
hsk_rs_worker_uninit(hsk_rs_worker_t *worker) {
  // Note that _uninit() is also used to clean up a partially-constructed
  // worker if _init() fails.

  // Can't destroy while still closing.
  assert(!worker->closing);

  // Can't destroy while worker is still running.
  assert(!worker->ub);

  free_async(worker->rs_quit_async);

  free_async(worker->rs_async);

  if (worker->rs_queue) {
    hsk_rs_queue_free(worker->rs_queue);
    worker->rs_queue = NULL;
  }
}

int
hsk_rs_worker_open(hsk_rs_worker_t *worker, struct ub_ctx *ub) {
  // Can't open if closing or already open.
  assert(!worker->closing);
  assert(!worker->ub);

  // Start the worker thread.  Set unbound context to indicate that the thread
  // is running.  If it starts, we can no longer write worker->ub from this
  // thread.
  worker->ub = ub;
  if (uv_thread_create(&worker->rs_thread, run_unbound_worker, (void *)worker)) {
    hsk_rs_worker_log(worker, "failed to create libuv worker thread");
    // Failed to start, not running.
    worker->ub = NULL;
    return HSK_EFAILURE;
  }

  return HSK_SUCCESS;
}

bool
hsk_rs_worker_is_open(hsk_rs_worker_t *worker) {
  // If we're closing, the worker is open, don't read ub.  Otherwise, we're open
  // if ub is set.
  return !worker->closing || worker->ub;
}

void
hsk_rs_worker_close(hsk_rs_worker_t *worker) {
  // No effect if already closing
  if (worker->closing)
    return;

  // Must be open
  assert(worker->ub);

  // Can't read worker->ub any more from the main thread once we tell the thread
  // to close.
  worker->closing = true;

  // We need to tell the libunbound worker to exit - wake up the thread and
  // clear ub on that thread.
  //
  // libunbound doesn't give us a good way to do this, the only way is to
  // issue a dummy query and do this in the callback on the worker thread.
  //
  // This works whether the request is successful or not.  As long as the
  // authoritative server initialized, it'll complete quickly (even if it could
  // not reach any peers).  If the authoritative server did not initialize, it
  // will unfortunately wait for a timeout.
  //
  // On Unix, we could poll unbound's file descriptor manually with another
  // file descriptor to allow us to wake the thread another way.  On Windows
  // though, libunbound does not provide any access to its WSAEVENT to do the
  // same thing; there's no other way to do this.
  hsk_rs_worker_log(worker, "stopping libunbound worker...\n");
  int rc = ub_resolve_async(worker->ub, ".", HSK_DNS_NS, HSK_DNS_IN,
                            (void *)worker, after_resolve_shutdown, NULL);
  if (rc != 0)
    hsk_rs_worker_log(worker, "cannot stop worker thread: %s\n", ub_strerror(rc));
}

hsk_rs_worker_t *
hsk_rs_worker_alloc(uv_loop_t *loop, void *stop_data,
                    void (*stop_callback)(void *)) {
  hsk_rs_worker_t *worker = malloc(sizeof(hsk_rs_worker_t));
  if (!worker)
    return NULL;

  if (hsk_rs_worker_init(worker, loop, stop_data, stop_callback) != HSK_SUCCESS) {
    free(worker);
    return NULL;
  }

  return worker;
}

void
hsk_rs_worker_free(hsk_rs_worker_t *worker) {
  if(worker) {
    hsk_rs_worker_uninit(worker);
    free(worker);
  }
}

int
hsk_rs_worker_resolve(hsk_rs_worker_t *worker, char *name, int rrtype,
                      int rrclass, void *data, ub_callback_type callback) {
  if (!callback)
    return HSK_EBADARGS;

  // Can't resolve when closing or not open
  if (worker->closing || !worker->ub)
    return HSK_EFAILURE;

  // Hold the callback data/func in a response object.  When the results come
  // in, we'll fill in the rest of this object and add it to the result queue.
  hsk_rs_rsp_t *rsp = malloc(sizeof(hsk_rs_rsp_t));
  rsp->next = NULL;
  rsp->cb_data = data;
  rsp->cb_func = callback;
  rsp->worker = worker;
  rsp->status = 0;

  int rc = ub_resolve_async(worker->ub, name, rrtype, rrclass, (void *)rsp,
                            after_resolve_onthread, NULL);
  if (rc) {
    hsk_rs_worker_log(worker, "unbound error: %s\n", ub_strerror(rc));
    return HSK_EFAILURE;
  }

  return HSK_SUCCESS;
}

static void
hsk_rs_worker_log(hsk_rs_worker_t *worker, const char *fmt, ...) {
  printf("rs_worker: ");

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

static uv_async_t *
alloc_async(hsk_rs_worker_t *worker, uv_loop_t *loop, uv_async_cb callback) {
  uv_async_t *async = malloc(sizeof(uv_async_t));
  if (!async) {
    hsk_rs_worker_log(worker, "out of memory");
    return NULL;
  }
  async->data = NULL;

  // Initialize the async
  if (uv_async_init(loop, async, callback)) {
    hsk_rs_worker_log(worker, "failed to create libuv async event");
    free(async);
    return NULL;
  }

  async->data = (void *)worker;

  return async;
}

static void
free_async(uv_async_t *async) {
  if(async) {
    async->data = NULL;
    hsk_uv_close_free((uv_handle_t *)async);
  }
}

static void
run_unbound_worker(void *arg) {
  hsk_rs_worker_t *worker = (hsk_rs_worker_t *)arg;

  while(worker->ub) {
    ub_wait(worker->ub);
  }

  uv_async_send(worker->rs_quit_async);
}

static void
after_resolve_shutdown(void *data, int status, struct ub_result *result) {
  ub_resolve_free(result);

  hsk_rs_worker_t *worker = (hsk_rs_worker_t *)data;

  // Clear this to stop the worker event loop.  This is safe because we've
  // synced up both threads to ensure they're not reading this - the main thread
  // won't read it any more at all (it's waiting for the worker thread to exit
  // after _close() was called), and we're inside a ub_wait() on the worker
  // thread.
  worker->ub = NULL;
}

// Handle a resolve result on the libunbound worker thread, dispatch back to the
// libuv event loop.
static void
after_resolve_onthread(void *data, int status, struct ub_result *result) {
  hsk_rs_rsp_t *rsp = (hsk_rs_rsp_t *)data;
  hsk_rs_worker_t *worker = rsp->worker;

  rsp->result = result;
  rsp->status = status;

  // Enqueue the response.  This is safe to do on the worker thread:
  // - The worker->rs_queue pointer is not modified after initialization until
  //   the worker thread has been stopped
  // - The hsk_rs_queue_t object itself is thread-safe
  hsk_rs_queue_enqueue(worker->rs_queue, rsp);

  // Queue an async event to process the response on the libuv event loop.
  // Like rs_queue, the rs_async pointer is safe to use because it's not
  // modified until the libunbound worker is stopped.
  uv_async_send(worker->rs_async);
}

static void
after_resolve_async(uv_async_t *async) {
  hsk_rs_worker_t *worker = (hsk_rs_worker_t *)async->data;

  // Since uv_close() is async, it might be possible to process this event after
  // the worker is destroyed but before the async is closed.
  if(!worker)
    return;

  // Dequeue and process all events in the queue - libuv coalesces calls to
  // uv_async_send().
  hsk_rs_rsp_t *rsp = hsk_rs_queue_dequeue(worker->rs_queue);
  while(rsp) {
    rsp->cb_func(rsp->cb_data, rsp->status, rsp->result);

    // Free the response element - the callback is responsible for the unbound
    // result
    free(rsp);

    rsp = hsk_rs_queue_dequeue(worker->rs_queue);
  }
}

static void
after_quit_async(uv_async_t *async) {
  hsk_rs_worker_t *worker = (hsk_rs_worker_t *)async->data;

  // Should never get this after worker is destroyed, the worker can't be
  // destroyed until _close() completes.
  assert(worker);

  worker->closing = false;

  hsk_rs_worker_log(worker, "libunbound worker stopped\n");

  // worker may be freed by this callback.
  worker->cb_stop_func(worker->cb_stop_data);
}
