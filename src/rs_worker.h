#ifndef _HSK_RS_WORKER_
#define _HSK_RS_WORKER_

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include <unbound.h>

#include "uv.h"

/*
 * Types
 */

struct _hsk_rs_rsp_t;
typedef struct _hsk_rs_rsp_t hsk_rs_rsp_t;

// Thread-safe response queue - synchronized with a mutex; responses enqueued
// from worker thread and dequeued on libuv event loop thread.
//
// This queue holds responses receieved from libunbound to dispatch them back
// to the libuv event loop.
typedef struct {
  uv_mutex_t mutex;
  hsk_rs_rsp_t *head;  // Oldest response
  hsk_rs_rsp_t *tail;  // Newest response
} hsk_rs_queue_t;

// Waitable pending request queue.  This holds requests that have been sent to
// libunbound until they receive a response on the libunbound worker thread.
//
// hsk_rs_pending_wait() waits until there is at least one pending request
// (returns immediately if it already is, otherwise blocks until it becomes
// nonzero).
//
// Also provides an 'exit' flag that tells the worker thread to exit.  A wait()
// ends when either the count is nonzero or the worker is supposed to exit.
typedef struct {
  // Mutex to protect count
  uv_mutex_t mutex;
  // Condition signaled whenever count is incremented
  uv_cond_t cond;
  // Linked list of outstanding requests
  hsk_rs_rsp_t *head; // Oldest request
  hsk_rs_rsp_t *tail; // Newest request
  // Whether worker should exit.
  bool exit;
} hsk_rs_pending_t;

// Response worker thread - relays libunbound results from its worker thread to
// the libuv event loop thread.
typedef struct {
  // Queue of results received from libunbound.
  hsk_rs_queue_t *rs_queue;
  // Pending request queue used to block the worker when no requests are being
  // serviced
  hsk_rs_pending_t *rs_pending;
  // Async used to signal results back to the libuv event loop.
  uv_async_t *rs_async;
  // Async used to signal that the worker thread is quitting (the worker can be
  // destroyed now)
  uv_async_t *rs_quit_async;
  uv_thread_t rs_thread;
  // Stop callback and data
  void *cb_stop_data;
  void (*cb_stop_func)(void *);
  // The unbound context processed by the worker thread.  Indicates whether the
  // worker thread event loop is running.
  // This is only written from the main thread while the worker is not running.
  struct ub_ctx *ub;
} hsk_rs_worker_t;

// Response data from libunbound - used to queue responses back to the libuv
// event loop in a linked list
struct _hsk_rs_rsp_t {
  hsk_rs_rsp_t *prev;
  hsk_rs_rsp_t *next;
  // Callback and data given to hsk_rs_worker_resolve()
  void *cb_data;
  ub_callback_type cb_func;
  // The worker that enqueued the response
  hsk_rs_worker_t *worker;
  // When the request is pending, the libunbound async ID
  int async_id;
  // After the response is enqueued, the result from libunbound
  struct ub_result *result;
  // Response status from libunbound
  int status;
};

/*
 * Response worker thread
 *
 * This manages async requests to libunbound and the worker thread that passes
 * results back to the libuv event loop.
 *
 * libunbound requests go through two queues:
 * - When the request is made, it enters the "pending request" queue
 *   (hsk_rs_pending_t)
 * - When the response is received from libunbound, it moves to the "response"
 *   queue (hsk_rs_queue_t)
 * - When the callback is delivered in the libuv event loop, it is removed from
 *   the response queue
 *
 * The two queues are necessary to avoid busy-waiting in the worker thread, to
 * hand responses back to the libuve event loop, and to be able to cancel
 * outstanding requests and shut down the worker thread.  They also ensure we
 * don't leak any memory for in-flight requests that are canceled at shutdown.
 */

// Initialize with the libuv event loop where results are handled and the
// libunbound context to process on the worker thread.  This starts the worker
// thread.
int
hsk_rs_worker_init(hsk_rs_worker_t *worker, uv_loop_t *loop, void *stop_data,
                   void (*stop_callback)(void *));

void
hsk_rs_worker_uninit(hsk_rs_worker_t *worker);

hsk_rs_worker_t *
hsk_rs_worker_alloc(uv_loop_t *loop, void *stop_data,
                    void (*stop_callback)(void *));

void
hsk_rs_worker_free(hsk_rs_worker_t *worker);

int
hsk_rs_worker_open(hsk_rs_worker_t *worker, struct ub_ctx *ub);

bool
hsk_rs_worker_is_open(hsk_rs_worker_t *worker);

// Close the worker.  The worker must be closed after it's successfully opened,
// and it can't be destroyed until the close completes (indicated by calling the
// stop_callback passed to _alloc()/_init()).
//
// Once _close() is called, calls to _resolve() will fail synchronously.
void
hsk_rs_worker_close(hsk_rs_worker_t *worker);

// Resolve a name.  The name, rrtype, and rrclass parameters are passed through
// to libunbound.  The result callback occurs in the libuv event loop.  When the
// callback occurs, ownership of the ub_result is passed to the callback.
int
hsk_rs_worker_resolve(hsk_rs_worker_t *worker, char *name, int rrtype,
                      int rrclass, void *data, ub_callback_type callback);

#endif
