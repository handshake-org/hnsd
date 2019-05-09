#ifndef _HSK_SIGNALS_H_
#define _HSK_SIGNALS_H_

#include <stdint.h>
#include <stdbool.h>

#include "signals.h"
#include "uv.h"

/*
 * Types
 */
typedef struct {
  void *cb_data;
  void (*cb_func)(void *);
  uv_signal_t *sigint;
  uv_signal_t *sigterm;
} hsk_signals_t;

/*
 * Signal handler
 *
 * Handles SIGINT and SIGTERM signals.  When one of these signals occurs, the
 * callback given is called in the libuv event loop.  (The callback should shut
 * down the process.)
 */
int
hsk_signals_init(hsk_signals_t *signals, uv_loop_t *loop, void *data,
                 void (*callback)());

void
hsk_signals_uninit(hsk_signals_t *signals);

hsk_signals_t *
hsk_signals_alloc(uv_loop_t *loop, void *data, void (*callback)());

void
hsk_signals_free(hsk_signals_t *signals);

#endif
