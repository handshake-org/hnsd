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
hsk_rs_pending_log(hsk_rs_pending_t *pending, const char *fmt, ...);

static void
hsk_rs_worker_log(hsk_rs_worker_t *ns, const char *fmt, ...);

static uv_async_t *
alloc_async(hsk_rs_worker_t *worker, uv_loop_t *loop, uv_async_cb callback);

static void
free_async(uv_async_t *async);

static void
run_unbound_worker(void *arg);

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

    // For responses still in the queue, call them now to ensure they don't
    // leak memory
    current->cb_func(current->cb_data, current->status, current->result);

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
    if(queue->head)
      queue->head->prev = NULL; // Removed the prior request
    else {
      assert(queue->tail == oldest); // There was only one request
      queue->tail = NULL;
    }
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
    rsp->prev = queue->tail;
    queue->tail = rsp;
  }

  uv_mutex_unlock(&queue->mutex);
}

/*
 * Pending Requests
 */
int
hsk_rs_pending_init(hsk_rs_pending_t *pending) {
  if (uv_mutex_init(&pending->mutex))
    return HSK_EFAILURE;
  if (uv_cond_init(&pending->cond)) {
    uv_mutex_destroy(&pending->mutex);
    return HSK_EFAILURE;
  }
  pending->head = NULL;
  pending->tail = NULL;
  pending->exit = false;

  return HSK_SUCCESS;
}

void
hsk_rs_pending_uninit(hsk_rs_pending_t *pending) {
  // There shouldn't be any outstanding requests, they would have been discarded
  // by _reset()
  assert(!pending->head);

  uv_cond_destroy(&pending->cond);
  uv_mutex_destroy(&pending->mutex);
}

hsk_rs_pending_t *
hsk_rs_pending_alloc() {
  hsk_rs_pending_t *pending = malloc(sizeof(hsk_rs_pending_t));
  if (!pending)
    return NULL;

  if (hsk_rs_pending_init(pending) != HSK_SUCCESS) {
    free(pending);
    return NULL;
  }

  return pending;
}

void
hsk_rs_pending_free(hsk_rs_pending_t *pending) {
  if(pending) {
    hsk_rs_pending_uninit(pending);
    free(pending);
  }
}

// Enqueue a pending request
void
hsk_rs_pending_enqueue(hsk_rs_pending_t *pending, hsk_rs_rsp_t *rsp) {
  uv_mutex_lock(&pending->mutex);

  if (!pending->tail) {
    assert(!pending->head);   // Invariant - set and cleared together
    pending->head = rsp;
    pending->tail = rsp;
  }
  else {
    pending->tail->next = rsp;
    rsp->prev = pending->tail;
    pending->tail = rsp;
  }

  uv_cond_signal(&pending->cond);
  uv_mutex_unlock(&pending->mutex);
}

// Remove a request that has received a response
void
hsk_rs_pending_remove(hsk_rs_pending_t *pending, hsk_rs_rsp_t *rsp) {
  uv_mutex_lock(&pending->mutex);

  // rsp must be in this queue, which means we must have at least one request
  // (rsp->prev and rsp->next could be NULL though if it is the only request)
  assert(pending->head);
  assert(pending->tail);

  if(rsp->prev) {
    rsp->prev->next = rsp->next;
  }
  else {
    assert(pending->head == rsp);   // head of list
    pending->head = rsp->next;  // NULL if this is the only request
  }

  if(rsp->next) {
    rsp->next->prev = rsp->prev;
  }
  else {
    assert(pending->tail == rsp);   // tail of list
    pending->tail = rsp->prev;
  }

  rsp->next = rsp->prev = NULL;

  uv_mutex_unlock(&pending->mutex);
}

// Signal the worker thread to exit.  Cancels all outstanding requests to
// libunbound.
void
hsk_rs_pending_exit(hsk_rs_pending_t *pending) {
  uv_mutex_lock(&pending->mutex);
  pending->exit = true;

  // The worker thread won't be able to exit until ub_wait() returns, which is
  // after all outstanding requests are resolved.  In the worst case, this could
  // take a few minutes to time out if nameservers are not responding (this is
  // not configurable in libunbound).
  //
  // We _could_ attempt to cancel the outstanding requests here, but then
  // ub_wait() seens to _never_ return, even if we issue another request to try
  // to kick it out of its wait.  libunbound might be leaking request counts
  // after cancelling a request.  Instead, just trace the outstanding requests.
  for(hsk_rs_rsp_t *current = pending->head; current; current = current->next) {
    hsk_rs_pending_log(pending, "still pending: %d\n", current->async_id);
  }

  uv_cond_signal(&pending->cond);
  uv_mutex_unlock(&pending->mutex);
}

// Check whether worker has been signaled to exit (including if it has exited)
bool
hsk_rs_pending_exiting(hsk_rs_pending_t *pending) {
  uv_mutex_lock(&pending->mutex);
  bool ret = pending->exit;
  uv_mutex_unlock(&pending->mutex);
  return ret;
}

// Reset after the worker thread has returned - clears exit flag and discards
// any remaining requests
void
hsk_rs_pending_reset(hsk_rs_pending_t *pending) {
  uv_mutex_lock(&pending->mutex);
  pending->exit = false;

  // There shouldn't be anything left at this point; _wait() does not indicate
  // to exit until there are no requests left _and_ exit is signaled.
  assert(!pending->head);
  assert(!pending->tail);

  uv_mutex_unlock(&pending->mutex);
}

// Wait until there is a pending request (returns true) or worker is signaled to exit
// (returns false)
bool
hsk_rs_pending_wait(hsk_rs_pending_t *pending) {
  uv_mutex_lock(&pending->mutex);
  while(!pending->head && !pending->exit) {
    // Wait until cond is signaled (count is incremented or thread is told to
    // exit)
    uv_cond_wait(&pending->cond, &pending->mutex);
  }
  // Return 'true' (process requests) if there is at least one outstanding
  // request, even if we are also signaled to exit.  We can't exit if a request
  // couldn't be canceled but hasn't been delivered yet; we would leak the
  // response object.
  bool ret = pending->head;
  uv_mutex_unlock(&pending->mutex);
  return ret;
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
  worker->rs_pending = NULL;
  worker->rs_async = NULL;
  worker->ub = NULL;
  worker->cb_stop_data = stop_data;
  worker->cb_stop_func = stop_callback;

  worker->rs_queue = hsk_rs_queue_alloc();
  if (!worker->rs_queue) {
    hsk_rs_worker_log(worker, "failed to create response queue");
    goto fail;
  }

  worker->rs_pending = hsk_rs_pending_alloc();
  if (!worker->rs_pending) {
    hsk_rs_worker_log(worker, "failed to create pending request queue");
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
  assert(!worker->rs_pending || !hsk_rs_pending_exiting(worker->rs_pending));

  // Can't destroy while worker is still running.
  assert(!worker->ub);

  free_async(worker->rs_quit_async);

  free_async(worker->rs_async);

  if (worker->rs_pending) {
    hsk_rs_pending_free(worker->rs_pending);
    worker->rs_pending = NULL;
  }

  if (worker->rs_queue) {
    hsk_rs_queue_free(worker->rs_queue);
    worker->rs_queue = NULL;
  }
}

int
hsk_rs_worker_open(hsk_rs_worker_t *worker, struct ub_ctx *ub) {
  // Can't open if closing or already open.
  assert(!hsk_rs_pending_exiting(worker->rs_pending));
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
  return worker->ub;
}

void
hsk_rs_worker_close(hsk_rs_worker_t *worker) {
  // No effect if already closing
  if (hsk_rs_pending_exiting(worker->rs_pending))
    return;

  // Must be open
  assert(worker->ub);

  // We need to tell the libunbound worker to exit - wake it up by signaling
  // the waitable count.
  //
  // This allows the worker thread to exit if nothing is going on in libunbound.
  // It could already be inside a ub_wait() though - if there are any ongoing
  // requests, this attempts to cancel them.  ub_wait() returns when there are
  // no more pending requests.
  hsk_rs_worker_log(worker, "stopping libunbound worker...\n");
  hsk_rs_pending_exit(worker->rs_pending);
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
  if (hsk_rs_pending_exiting(worker->rs_pending) || !worker->ub)
    return HSK_EFAILURE;

  // Hold the callback data/func in a response object.  When the results come
  // in, we'll fill in the rest of this object and add it to the result queue.
  hsk_rs_rsp_t *rsp = malloc(sizeof(hsk_rs_rsp_t));
  rsp->prev = rsp->next = NULL;
  rsp->cb_data = data;
  rsp->cb_func = callback;
  rsp->worker = worker;
  rsp->async_id = 0;
  rsp->result = NULL;
  rsp->status = 0;

  // Enqueue before attempting to send; we have to do this before sending to
  // avoid racing with the callback.
  hsk_rs_pending_enqueue(worker->rs_pending, rsp);

  int rc = ub_resolve_async(worker->ub, name, rrtype, rrclass, (void *)rsp,
                            after_resolve_onthread, &rsp->async_id);
  if (rc) {
    // Remove the response since it couldn't be sent.
    hsk_rs_pending_remove(worker->rs_pending, rsp);
    hsk_rs_worker_log(worker, "unbound error: %s\n", ub_strerror(rc));
    return HSK_EFAILURE;
  }
  hsk_rs_worker_log(worker, "request %d: %s\n", rsp->async_id, name);

  return HSK_SUCCESS;
}

static void
hsk_rs_pending_log(hsk_rs_pending_t *pending, const char *fmt, ...) {
  printf("rs_pending: ");

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
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

  // Annoyingly, ub_wait() does not actually wait if there are no outstanding
  // requests.  To prevent a busy-wait when there's no work to do, we have to
  // keep track of the outstanding requests manually and use a condition
  // variable to block on them.  (libunbound already knows the count, but it
  // doesn't give us any access to it.)
  while(hsk_rs_pending_wait(worker->rs_pending)) {
    // Not modified while worker is running
    assert(worker->ub);
    ub_wait(worker->ub);
  }

  // hsk_rs_pending_wait() returned false; worker was signaled to exit.
  uv_async_send(worker->rs_quit_async);
}

// Handle a resolve result on the libunbound worker thread, dispatch back to the
// libuv event loop.
static void
after_resolve_onthread(void *data, int status, struct ub_result *result) {
  hsk_rs_rsp_t *rsp = (hsk_rs_rsp_t *)data;
  hsk_rs_worker_t *worker = rsp->worker;

  rsp->result = result;
  rsp->status = status;

  // This request finished, remove it from the pending queue.
  hsk_rs_pending_remove(worker->rs_pending, rsp);

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

  uv_thread_join(&worker->rs_thread);

  hsk_rs_pending_reset(worker->rs_pending);
  // Worker has exited, could be opened again at this point
  worker->ub = NULL;

  hsk_rs_worker_log(worker, "libunbound worker stopped\n");

  // worker may be freed by this callback.
  worker->cb_stop_func(worker->cb_stop_data);
}
