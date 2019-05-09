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
typedef struct {
  uv_mutex_t mutex;
  hsk_rs_rsp_t *head;  // Oldest response
  hsk_rs_rsp_t *tail;  // Newest response
} hsk_rs_queue_t;

// Response worker thread - relays libunbound results from its worker thread to
// the libuv event loop thread.
typedef struct {
  // Queue of results received from libunbound.
  hsk_rs_queue_t *rs_queue;
  // Async used to signal back to the libuv event loop.
  uv_async_t *rs_async;
  uv_thread_t rs_thread;
  // The unbound context processed by the worker thread.  Indicates whether the
  // worker thread event loop is running.
  struct ub_ctx *ub;
} hsk_rs_worker_t;

// Response data from libunbound - used to queue responses back to the libuv
// event loop in a linked list
struct _hsk_rs_rsp_t {
  hsk_rs_rsp_t *next;
  // Callback and data given to hsk_rs_worker_resolve()
  void *cb_data;
  ub_callback_type cb_func;
  union {
    // Before the response is received, store a pointer back to the worker so we
    // can enqueue the response.
    hsk_rs_worker_t *worker;
    // After the response is enqueued, store the result from libunbound
    struct ub_result *result;
  };
  // Response status from libunbound
  int status;
};

/*
 * Response worker thread
 */

// Initialize with the libuv event loop where results are handled and the
// libunbound context to process on the worker thread.  This starts the worker
// thread.
int
hsk_rs_worker_init(hsk_rs_worker_t *worker, uv_loop_t *loop, struct ub_ctx *ub);

void
hsk_rs_worker_uninit(hsk_rs_worker_t *worker);

hsk_rs_worker_t *
hsk_rs_worker_alloc(uv_loop_t *loop, struct ub_ctx *ub);

void
hsk_rs_worker_free(hsk_rs_worker_t *worker);

// Resolve a name.  The name, rrtype, and rrclass parameters are passed through
// to libunbound.  The result callback occurs in the libuv event loop.  When the
// callback occurs, ownership of the ub_result is passed to the callback.
int
hsk_rs_worker_resolve(hsk_rs_worker_t *worker, char *name, int rrtype,
                      int rrclass, void *data, ub_callback_type callback);

#endif
