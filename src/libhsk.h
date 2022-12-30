#include <stdint.h>
#include <stdbool.h>

#include "uv.h"

typedef struct hsk_ctx_s {
  void *loop; // uv_loop_t  (uv.h)
  void *pool; // hsk_pool_t (pool.h)
} hsk_ctx_t;

// hsk_resolve_cb (pool.h)
typedef void (*hsk_ctx_resolve_cb)(
  const char *name,
  int status,
  bool exists,
  const uint8_t *data,
  size_t data_len,
  const void *arg
);

void
hsk_ctx_destroy(hsk_ctx_t *ctx);

hsk_ctx_t *
hsk_ctx_create(int pool_size, char *user_agent, char *prefix);

int
hsk_ctx_open(hsk_ctx_t *ctx);

void
hsk_ctx_close(hsk_ctx_t *ctx);

float
hsk_ctx_get_sync_progress(hsk_ctx_t *ctx);

int
hsk_ctx_resolve(
  hsk_ctx_t *ctx,
  const char *name,
  hsk_ctx_resolve_cb callback,
  const void *arg
);
