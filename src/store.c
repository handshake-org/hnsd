#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>

#include "bio.h"
#include "constants.h"
#include "error.h"
#include "header.h"
#include "store.h"
#include "uv.h"

#if defined(_WIN32)
#  include <windows.h>
#  define HSK_PATH_SEP '\\'
#else
#  include <sys/stat.h>
#  define HSK_PATH_SEP '/'
#endif


static void
hsk_store_log(const char *fmt, ...) {
  printf("store: ");

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

bool
hsk_store_exists(char *path) {
#if defined(_WIN32)
  return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
#else
  struct stat st;
  return lstat(path, &st) == 0;
#endif
}

static void
hsk_store_filename(char *prefix, char *path, bool tmp) {
  sprintf(
    path,
    "%s%c%s_%s%s%c",
    prefix,
    HSK_PATH_SEP,
    HSK_STORE_FILENAME,
    HSK_NETWORK_NAME,
    HSK_STORE_EXTENSION,
    tmp ? '~' : '\0'
  );
}

static void
hsk_store_after_close(uv_fs_t *req_close) {
  hsk_store_ctx_t *ctx = (hsk_store_ctx_t *)req_close->data;

  if (req_close->result < 0) {
    hsk_store_log("(%u) could not close checkpoint file\n", ctx->height);
    goto done;
  }

#if defined(_WIN32)
  // Can not do the rename-file trick to guarantee atomicity on windows
  // so delete existing file if present
  remove(ctx->path); // TODO replace with uv_fs_unlink
#endif

  // Replace actual file with temp for atomicity
  rename(ctx->tmp, ctx->path); // TODO replace with uv_fs_rename

  hsk_store_log(
    "(%u) checkpoint file written to path: %s\n",
    ctx->height,
    ctx->path
  );

done:
  uv_fs_req_cleanup(req_close);
  free(ctx);
}

static void
hsk_store_after_write(uv_fs_t *req_write) {
  hsk_store_ctx_t *ctx = (hsk_store_ctx_t *)req_write->data;

  if (req_write->result < 0) // should be bytes written
    goto fail;

  // Close file
  uv_fs_t req_close;
  req_close.data = req_write->data;
  uv_fs_close(
    req_write->loop,
    &req_close,
    ctx->file, // file handle
    NULL // sync
  );

  hsk_store_after_close(&req_close);

  goto done;

fail:
  hsk_store_log(
    "(%u) could not write checkpoint file\n",
    ctx->height,
    req_write->result
  );

  free(ctx);

done:
  uv_fs_req_cleanup(req_write);
  free(req_write);
}

void
hsk_store_write(const hsk_chain_t *chain) {
  // Prepare
  hsk_store_ctx_t *ctx = malloc(sizeof(hsk_store_ctx_t));
  if (!ctx)
    goto fail;
  hsk_store_filename(chain->prefix, ctx->tmp, true);
  hsk_store_filename(chain->prefix, ctx->path, false);

  // Serialize
  char buf[HSK_STORE_CHECKPOINT_SIZE];
  uint8_t *data = (uint8_t *)&buf;

  if (!write_u32be(&data, HSK_MAGIC))
    goto fail;

  if (!write_u8(&data, HSK_STORE_VERSION))
    goto fail;

  uint32_t height = chain->height - HSK_STORE_CHECKPOINT_WINDOW;
  ctx->height = height;
  if (!write_u32be(&data, height))
    goto fail;

  hsk_header_t *prev = hsk_chain_get_by_height(chain, height - 1);
  if (!write_bytes(&data, prev->work, 32))
    goto fail;

  for (int i = 0; i < HSK_STORE_HEADERS_COUNT; i++) {
    hsk_header_t *hdr = hsk_chain_get_by_height(chain, i + height);

    if (!hsk_header_write(hdr, &data))
      goto fail;
  }

  uv_buf_t uvbuf;
  uvbuf.base = buf;
  uvbuf.len = HSK_STORE_CHECKPOINT_SIZE;

  // Open file
  uv_fs_t req_open;
  uv_fs_open(
    chain->loop,
    &req_open,
    ctx->tmp,
    UV_FS_O_CREAT | UV_FS_O_WRONLY | UV_FS_O_TRUNC,
    S_IRUSR | S_IWUSR,
    NULL // sync
  );

  if (req_open.result < 0) // should be file handle
    goto fail;

  ctx->file = req_open.result;

  hsk_store_log("(%u) writing checkpoint file: %s\n", ctx->height, ctx->tmp);

  // Write async
  uv_fs_t *req_write = malloc(sizeof(uv_fs_t));
  req_write->data = ctx;

  uv_fs_write(
    chain->loop,
    req_write,
    req_open.result, // file handle
    &uvbuf,
    1,  // number of buffers
    0,  // start position
    hsk_store_after_write
  );

  goto done;

fail:
  hsk_store_log("could not initialize checkpoint file\n");

  if (ctx)
    free(ctx);

done:
  uv_fs_req_cleanup(&req_open);
}

bool
hsk_store_inject_checkpoint(
  uint8_t **data,
  size_t *data_len,
  hsk_chain_t *chain
) {
  // Checkpoint start height
  if (!read_u32be(data, data_len, &chain->init_height))
    return false;

  hsk_store_log(
    "injecting checkpoint into chain from height %d\n", 
    chain->init_height
  );

  // Insert the total chainwork up to this point
  hsk_header_t prev;
  hsk_header_t *prev_ptr = &prev;
  if (!read_bytes(data, data_len, prev.work, 32))
    return false;

  // Insert headers, assume valid
  for (int i = 0; i < HSK_STORE_HEADERS_COUNT; i++) {
    // Read raw header
    hsk_header_t *hdr = hsk_header_alloc();
    if (!hsk_header_read(data, data_len, hdr))
      return false;

    // Compute and cache hash
    assert(hsk_header_cache(hdr));

    // Set height
    hdr->height = chain->init_height + i;

    // Sanity check: headers should connect
    if (i > 0) {
      assert(
        memcmp(hdr->prev_block, prev_ptr->hash, 32) == 0
        && "invalid checkpoint: prev"
      );
    }

    // Compute and set total chain work
    assert(hsk_header_calc_work(hdr, prev_ptr));


    if (hsk_chain_save(chain, hdr) != 0)
      return false;

    prev_ptr = hdr;
  }

  return true;
}

bool
hsk_store_read(
  uint8_t **data,
  size_t *data_len,
  hsk_chain_t *chain
) {
  char path[HSK_STORE_PATH_MAX];
  hsk_store_filename(chain->prefix, path, false);

  hsk_store_log("loading checkpoint from file: %s\n", path);

  FILE *file = fopen(path, "r");
  if (!file)
    return false;

  // Synchronous, only run once on startup to initialize chain
  size_t read = fread(*data, 1, HSK_STORE_CHECKPOINT_SIZE, file);
  if (read != HSK_STORE_CHECKPOINT_SIZE)
    return false;
  fclose(file);

  uint32_t magic;
  if (!read_u32be(data, data_len, &magic))
    return false;

  if (magic != HSK_MAGIC)
    return false;

  uint8_t version;
  if (!read_u8(data, data_len, &version))
    return false;

  if (version != HSK_STORE_VERSION)
    return false;

  return true;
}
