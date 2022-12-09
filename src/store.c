#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>

#include "bio.h"
#include "chain.h"
#include "constants.h"
#include "error.h"
#include "header.h"
#include "store.h"

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
hsk_store_filename(char *prefix, char *path, uint32_t height) {
  sprintf(
    path,
    "%s%c%s_%s%s",
    prefix,
    HSK_PATH_SEP,
    HSK_STORE_FILENAME,
    HSK_NETWORK_NAME,
    HSK_STORE_EXTENSION
  );

  if (height > 0) {
    sprintf(path, "%s~%u", path, height);
  }
}

void
hsk_store_write(const hsk_chain_t *chain) {
  // Serialize
  char buf[HSK_STORE_CHECKPOINT_SIZE];
  uint8_t *data = (uint8_t *)&buf;

  if (!write_u32be(&data, HSK_MAGIC))
    goto fail;

  if (!write_u8(&data, HSK_STORE_VERSION))
    goto fail;

  assert(chain->height % HSK_STORE_CHECKPOINT_WINDOW == 0);
  uint32_t height = chain->height - HSK_STORE_CHECKPOINT_WINDOW;
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

  // Prepare
  char path[HSK_STORE_PATH_MAX];
  char tmp[HSK_STORE_PATH_MAX];
  hsk_store_filename(chain->prefix, tmp, height);
  hsk_store_filename(chain->prefix, path, 0);

  // Open file
  FILE *file = fopen(tmp, "w");
  if (!file) {
    hsk_store_log("could not open temp file to write checkpoint: %s\n", tmp);
    return;
  }

  // Write temp
  size_t written = fwrite(&buf, 1, HSK_STORE_CHECKPOINT_SIZE, file);
  fclose(file);

  if (written != HSK_STORE_CHECKPOINT_SIZE) {
    hsk_store_log("could not write checkpoint to temp file: %s\n", tmp);
    return;
  } else {
    hsk_store_log("(%u) wrote temp checkpoint file: %s\n", height, tmp);
  }

  // Rename
#if defined(_WIN32)
  // Can not do the rename-file trick to guarantee atomicity on windows
  remove(path);
#endif
 
  if (rename(tmp, path) == 0) {
    hsk_store_log("(%u) wrote checkpoint file: %s\n", height, path);
    return;
  } else {
    hsk_store_log("(%u) failed to write checkpoint file: %s\n", height, path);
    return;
  }

fail:
  hsk_store_log("could not serialize checkpoint data\n");
}

bool
hsk_store_inject_checkpoint(
  uint8_t **data,
  size_t *data_len,
  hsk_chain_t *chain
) {
  // Checkpoint start height
  uint32_t height;
  if (!read_u32be(data, data_len, &height))
    return false;

  // Could be conflict between checkpoint file on disk
  // and hard-coded checkpoint. Go with highest.
  if (chain->init_height >= height) {
    hsk_store_log(
      "ignoring checkpoint at height %d, chain already initialized at %d\n",
      height,
      chain->init_height
    );
    return true;
  }

  chain->init_height = height;
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
  hsk_store_filename(chain->prefix, path, 0);

  hsk_store_log("loading checkpoint from file: %s\n", path);

  // Open
  FILE *file = fopen(path, "r");
  if (!file) {
    hsk_store_log("could not open checkpoint file: %s\n", path);
    return false;
  }

  // Read
  size_t read = fread(*data, 1, *data_len, file);
  fclose(file);

  if (read != *data_len) {
    hsk_store_log("could not read checkpoint file: %s\n", path);
    return false;
  }

  uint32_t magic;
  if (!read_u32be(data, data_len, &magic)) {
    hsk_store_log("could not read magic from checkpoint file: %s\n", path);
    return false;
  }

  if (magic != HSK_MAGIC) {
    hsk_store_log("invalid magic bytes in checkpoint file: %s\n", path);
    return false;
  }

  uint8_t version;
  if (!read_u8(data, data_len, &version)) {
    hsk_store_log("could not read version from checkpoint file: %s\n", path);
    return false;
  }

  if (version != HSK_STORE_VERSION){
    hsk_store_log("invalid version in checkpoint file: %s\n", path);
    return false;
  }

  return true;
}
