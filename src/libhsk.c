#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include <sys/types.h>
#include <unistd.h>

#include "constants.h"
#include "hsk.h"
#include "libhsk.h"
#include "pool.h"
#include "uv.h"
#include "platform-net.h"

void
hsk_ctx_destroy(hsk_ctx_t *ctx) {
  if (!ctx)
    return;

  if (ctx->pool) {
    hsk_pool_free((hsk_pool_t *)ctx->pool);
    ctx->pool = NULL;
  }

  if (ctx->loop) {
    uv_loop_close((uv_loop_t *)ctx->loop);
    ctx->loop = NULL;
  }

  free(ctx);
}

hsk_ctx_t *
hsk_ctx_create(int pool_size, char *user_agent, char *prefix) {
  assert(pool_size && user_agent && prefix);

  // Prefix must exist
  if (!hsk_store_exists(prefix)) {
    fprintf(stderr, "prefix path does not exist\n");
    return NULL;
  }

  // Prefix must have enough room for filename
  if (strlen(prefix) + HSK_STORE_PATH_RESERVED >= HSK_STORE_PATH_MAX) {
    fprintf(stderr, "prefix path is too long\n");
    return NULL;
  }

  // Init context
  hsk_ctx_t *ctx = malloc(sizeof(hsk_ctx_t));
  if (!ctx) {
    fprintf(stderr, "could not initialize context\n");
    return NULL;
  }

  // Init loop
  ctx->loop = uv_default_loop();
  if (!ctx->loop) {
    fprintf(stderr, "could not initialize loop\n");
    goto done;
  }

  uv_loop_t *loop = (uv_loop_t *)ctx->loop;

  // Init pool
  ctx->pool = hsk_pool_alloc(loop);
  if(!ctx->pool) {
    fprintf(stderr, "could not initialize pool\n");
    goto done;
  }

  hsk_pool_t *pool = (hsk_pool_t *)ctx->pool;

  if (!hsk_pool_set_size(pool, pool_size)){
    fprintf(stderr, "could not set pool size\n");
    goto done;
  }

  if (!hsk_pool_set_agent(pool, user_agent)){
    fprintf(stderr, "could not set pool agent\n");
    goto done;
  }

  pool->chain.prefix = prefix;

  return ctx;

done:
  hsk_ctx_destroy(ctx);
  return NULL;
}

int
hsk_ctx_open(hsk_ctx_t *ctx) {
  assert(ctx);
  int rc = HSK_SUCCESS;
  hsk_pool_t *pool = (hsk_pool_t *)ctx->pool;
  uv_loop_t *loop = (uv_loop_t *)ctx->loop;

  // Always load hard-coded checkpoint
  {
    uint8_t *data = (uint8_t *)HSK_CHECKPOINT;
    size_t data_len = HSK_STORE_CHECKPOINT_SIZE;
    if (!hsk_store_inject_checkpoint(&data, &data_len, &pool->chain)) {
      fprintf(stderr, "unable to inject hard-coded checkpoint\n");
      return HSK_EBADARGS;
    }
  }

  // Maybe load the last saved runtime checkpoint from file
  {
    uint8_t data[HSK_STORE_CHECKPOINT_SIZE];
    uint8_t *data_ptr = (uint8_t *)&data;
    size_t data_len = HSK_STORE_CHECKPOINT_SIZE;
    if (hsk_store_read(&data_ptr, &data_len, &pool->chain)) {
      if (!hsk_store_inject_checkpoint(
        &data_ptr,
        &data_len,
        &pool->chain
      )) {
        fprintf(stderr, "unable to inject checkpoint from file\n");
        return HSK_EBADARGS;
      } else {
        // Success, checkpoint loaded
      }
    } else {
      // Could not read file, might not exist, ignore
    }
  }

  rc = hsk_pool_open(pool);
  if (rc != HSK_SUCCESS) {
    fprintf(stderr, "failed opening pool: %s\n", hsk_strerror(rc));
    goto done;
  }

  rc = uv_run(loop, UV_RUN_DEFAULT);
  if (rc != 0) {
    fprintf(stderr, "failed running event loop: %s\n", uv_strerror(rc));
    rc = HSK_EFAILURE;
    goto done;
  }

done:
  hsk_ctx_destroy(ctx);
  return rc;
}

void
hsk_ctx_close(hsk_ctx_t *ctx) {
   hsk_pool_t *pool = (hsk_pool_t *)ctx->pool;
   hsk_pool_destroy(pool);
   ctx->pool = NULL;
}

float
hsk_ctx_get_sync_progress(hsk_ctx_t *ctx) {
  hsk_pool_t *pool = (hsk_pool_t *)ctx->pool;
  return hsk_chain_progress(&pool->chain);
}

int
hsk_ctx_resolve(
  hsk_ctx_t *ctx,
  const char *name,
  hsk_ctx_resolve_cb callback,
  const void *arg
) {
  hsk_pool_t *pool = (hsk_pool_t *)ctx->pool;
  return hsk_pool_resolve(pool, name, callback, arg);
}
