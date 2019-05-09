#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <unbound.h>

#include "dns.h"
#include "error.h"
#include "rs_worker.h"
#include "uv.h"

/*
 * Prototypes
 */
static void
hsk_rs_worker_log(hsk_rs_worker_t *ns, const char *fmt, ...);

static void
after_close_free(uv_handle_t *handle);

static void
run_unbound_worker(void *arg);

static void
after_resolve_shutdown(void *data, int status, struct ub_result *result);

static void
after_resolve_onthread(void *data, int status, struct ub_result *result);

static void
after_resolve_async(uv_async_t *async);

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
hsk_rs_worker_init(hsk_rs_worker_t *worker, uv_loop_t *loop, struct ub_ctx *ub) {
  if (!worker || !loop || !ub)
    return HSK_EBADARGS;

  worker->rs_queue = NULL;
  worker->rs_async = NULL;
  worker->ub = NULL;

  worker->rs_queue = hsk_rs_queue_alloc();
  if (!worker->rs_queue) {
    hsk_rs_worker_log(worker, "failed to create response queue");
    goto fail;
  }

  // Allocate this separately on the heap because uv_close() is asynchronous.
  worker->rs_async = malloc(sizeof(uv_async_t));
  if (!worker->rs_async) {
    hsk_rs_worker_log(worker, "out of memory");
    goto fail;
  }

  // Initialize the async and set data if successful.  (This also indicates to
  // the cleanup logic that the async needs to be closed.)
  worker->rs_async->data = NULL;
  if (uv_async_init(loop, worker->rs_async, after_resolve_async)) {
    hsk_rs_worker_log(worker, "failed to create libuv async event");
    goto fail;
  }
  worker->rs_async->data = (void *)worker;

  // Start the worker thread.  Set unbound context to indicate that the thread
  // is running.  If it starts, we can no longer write worker->ub until we sync
  // up both threads again in _uninit().
  worker->ub = ub;
  if (uv_thread_create(&worker->rs_thread, run_unbound_worker, (void *)worker)) {
    hsk_rs_worker_log(worker, "failed to create libuv worker thread");
    // Failed to start, not running.
    worker->ub = NULL;
    goto fail;
  }

  return HSK_SUCCESS;

fail:
  hsk_rs_worker_uninit(worker);

  return HSK_EFAILURE;
}

void
hsk_rs_worker_uninit(hsk_rs_worker_t *worker) {
  // Note that _uninit() is also used to clean up a partially-constructed
  // worker if _init() fails.

  if (worker->ub) {
    // We need to tell the libunbound worker to exit - wake up the thread and
    // clear ub on that thread.
    //
    // libunbound doesn't give us a good way to do this, the only way is to
    // issue a dummy query and do this in the callback on the worker thread.
    //
    // On Unix, we could poll unbound's file descriptor manually with another
    // file descriptor to allow us to wake the thread another way.  On Windows
    // though, libunbound does not provide any access to its WSAEVENT to do the
    // same thing; there's no other way to do this.
    int rc = ub_resolve_async(worker->ub, ".", HSK_DNS_NS, HSK_DNS_IN,
                              (void *)worker, after_resolve_shutdown, NULL);
    if (rc != 0)
      hsk_rs_worker_log(worker, "cannot shut down worker thread: %s\n", ub_strerror(rc));
    else
      uv_thread_join(&worker->rs_thread);
  }

  if (worker->rs_async) {
    // If it was also initialized, close it and free asynchronously
    if (worker->rs_async->data) {
      worker->rs_async->data = NULL;
      uv_close((uv_handle_t *)worker->rs_async, after_close_free);
      worker->rs_async = NULL;
    }
    else {
      // Wasn't initialized, just free memory
      free(worker->rs_async);
      worker->rs_async = NULL;
    }
  }

  if (worker->rs_queue) {
    hsk_rs_queue_free(worker->rs_queue);
    worker->rs_queue = NULL;
  }
}

hsk_rs_worker_t *
hsk_rs_worker_alloc(uv_loop_t *loop, struct ub_ctx *ub) {
  hsk_rs_worker_t *worker = malloc(sizeof(hsk_rs_worker_t));
  if (!worker)
    return NULL;

  if (hsk_rs_worker_init(worker, loop, ub) != HSK_SUCCESS) {
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

static void
after_close_free(uv_handle_t *handle) {
  free(handle);
}

static void
run_unbound_worker(void *arg) {
  hsk_rs_worker_t *worker = (hsk_rs_worker_t *)arg;

  while(worker->ub) {
    ub_wait(worker->ub);
  }
}

static void
after_resolve_shutdown(void *data, int status, struct ub_result *result) {
  ub_resolve_free(result);

  hsk_rs_worker_t *worker = (hsk_rs_worker_t *)data;

  // Clear this to stop the worker event loop.  This is safe because we've
  // synced up both threads to ensure they're not reading this - the main thread
  // won't read it any more at all (it's just going to wait for the worker to
  // exit with a _join()), and we're inside a ub_wait() on the worker thread.
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
  hsk_rs_worker_t *worker = async->data;

  // Since uv_close() is async, it might be possible to process this event after
  // the worker is shut down but before the async is closed.
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
