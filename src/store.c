#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "bio.h"
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

bool
hsk_store_exists(char *path) {
#if defined(_WIN32)
  return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
#else
  struct stat st;
  return lstat(path, &st) == 0;
#endif
}

static int
hsk_store_filename(char *prefix, char *path) {
  sprintf(
    path,
    "%s%c%s_%s%s",
    prefix,
    HSK_PATH_SEP,
    HSK_STORE_FILENAME,
    HSK_NETWORK_NAME,
    HSK_STORE_EXTENSION
  );

  return HSK_SUCCESS;
}

bool
hsk_store_checkpoint_read(
  uint8_t **data,
  size_t *data_len,
  hsk_checkpoint_t *checkpoint
) {
  if (!read_u32be(data, data_len, &checkpoint->height))
    return false;

  if (!read_bytes(data, data_len, (uint8_t *)checkpoint->chainwork, 32))
    return false;

  for (int i = 0; i < HSK_STORE_HEADERS_COUNT; i++) {
    hsk_header_t *hdr = hsk_header_alloc();
    if (!hsk_header_read(data, data_len, hdr))
      return false;
    checkpoint->headers[i] = hdr;
  }

  return true;
}

bool
hsk_store_write(hsk_checkpoint_t *checkpoint, char *prefix) {
  // Serialize
  uint8_t buf[HSK_STORE_CHECKPOINT_SIZE];
  uint8_t *data = (uint8_t *)&buf;

  if (!write_u32be(&data, HSK_MAGIC))
    return false;

  if (!write_u8(&data, HSK_STORE_VERSION))
    return false;

  if (!write_u32be(&data, checkpoint->height))
    return false;

  if (!write_bytes(&data, checkpoint->chainwork, 32))
    return false;

  for (int i = 0; i < HSK_STORE_HEADERS_COUNT; i++) {
    hsk_header_t *hdr = checkpoint->headers[i];

    if (!hsk_header_write(hdr, &data))
      return false;
  }

  // Write
  char path[HSK_STORE_PATH_MAX];
  hsk_store_filename(prefix, path);
  FILE *file = fopen(path, "w");
  if (!file)
    return false;
  size_t written = fwrite(&buf, 1, HSK_STORE_CHECKPOINT_SIZE, file);
  fclose(file);
  return written == HSK_STORE_CHECKPOINT_SIZE;
}

bool
hsk_store_read(hsk_checkpoint_t *checkpoint, char *prefix) {
  uint8_t buf[HSK_STORE_CHECKPOINT_SIZE];
  uint8_t *data = (uint8_t *)&buf;
  size_t data_len = HSK_STORE_CHECKPOINT_SIZE;

  char path[HSK_STORE_PATH_MAX];
  hsk_store_filename(prefix, path);
  FILE *file = fopen(path, "r");
  if (!file)
    return false;

  size_t read = fread(buf, 1, HSK_STORE_CHECKPOINT_SIZE, file);
  if (read != HSK_STORE_CHECKPOINT_SIZE)
    return false;
  fclose(file);

  uint32_t magic;
  if (!read_u32be(&data, &data_len, &magic))
    return false;

  if (magic != HSK_MAGIC)
    return false;

  uint8_t version;
  if (!read_u8(&data, &data_len, &version))
    return false;

  if (version != HSK_STORE_VERSION)
    return false;

  return hsk_store_checkpoint_read(&data, &data_len, checkpoint);
}
