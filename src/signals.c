#include "config.h"

#include "error.h"
#include "signals.h"
#include "utils.h"

/*
 * Prototypes
 */
static uv_signal_t *
alloc_signal(hsk_signals_t *signals, uv_loop_t *loop, int signum);

static void
free_signal(uv_signal_t *signal);

static void
signal_handler(uv_signal_t *signal, int signum);

/*
 * Signal handler
 */
int
hsk_signals_init(hsk_signals_t *signals, uv_loop_t *loop, void *data,
                 void (*callback)()) {
  if (!signals || !loop || !callback)
    return HSK_EBADARGS;

  signals->cb_data = data;
  signals->cb_func = callback;

  signals->sigint = alloc_signal(signals, loop, SIGINT);
  if (!signals->sigint)
    goto fail;

  signals->sigterm = alloc_signal(signals, loop, SIGTERM);
  if (!signals->sigterm)
    goto fail;

  return HSK_SUCCESS;

fail:
  hsk_signals_uninit(signals);

  return HSK_EFAILURE;
}

void
hsk_signals_uninit(hsk_signals_t *signals) {
  free_signal(signals->sigterm);
  signals->sigterm = NULL;
  free_signal(signals->sigint);
  signals->sigterm = NULL;
}

hsk_signals_t *
hsk_signals_alloc(uv_loop_t *loop, void *data, void (*callback)()) {
  hsk_signals_t *signals = malloc(sizeof(hsk_signals_t));
  if (!signals)
    return NULL;

  if (hsk_signals_init(signals, loop, data, callback) != HSK_SUCCESS) {
    free(signals);
    return NULL;
  }

  return signals;
}

void
hsk_signals_free(hsk_signals_t *signals) {
  if (signals) {
    hsk_signals_uninit(signals);
    free(signals);
  }
}

static uv_signal_t *
alloc_signal(hsk_signals_t *signals, uv_loop_t *loop, int signum) {
  // Allocate the signal
  uv_signal_t *signal = malloc(sizeof(uv_signal_t));
  if (!signal)
    return NULL;

  signal->data = NULL;

  // Init the signal
  if (uv_signal_init(loop, signal)) {
    free(signal);
    return NULL;
  }

  if (uv_signal_start(signal, signal_handler, signum))
  {
    // Free after async close
    hsk_uv_close_free((uv_handle_t *)signal);
    return NULL;
  }

  signal->data = (void *)signals;

  return signal;
}

static void
free_signal(uv_signal_t *signal) {
  if (signal) {
    signal->data = NULL;
    uv_signal_stop(signal);
    hsk_uv_close_free((uv_handle_t *)signal);
  }
}

static void
signal_handler(uv_signal_t *signal, int signum) {
  hsk_signals_t *signals = (hsk_signals_t *)signal->data;

  // Due to async close, might be possible to receive this after _uninit()
  if (!signals)
    return;

  printf("signal: %d\n", signum);

  signals->cb_func(signals->cb_data);
}
