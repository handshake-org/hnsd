#ifndef _HSK_STORE
#define _HSK_STORE

#include "header.h"

/*
 * Defs
 */

// Version 0 header store file serialization:
// Size    Data
//  4       network magic
//  1       version (0)
//  4       start height
//  32      total chainwork excluding block at start height
//  35400   150 x 236-byte serialized block headers

#define HSK_STORE_VERSION 0
#define HSK_STORE_HEADERS_COUNT 150
#define HSK_STORE_CHECKPOINT_SIZE 35441
#define HSK_STORE_CHECKPOINT_WINDOW 2000
#define HSK_STORE_FILENAME "checkpoint"
#define HSK_STORE_EXTENSION ".dat"
#define HSK_STORE_PATH_MAX 1024

/*
 * Types
 */

typedef struct {
  uint32_t height;
  uint8_t chainwork[32];
  hsk_header_t *headers[HSK_STORE_HEADERS_COUNT];
} hsk_checkpoint_t;

/*
 * Store
 */

bool
hsk_store_exists(char *path);

bool
hsk_store_checkpoint_read(
  uint8_t **data,
  size_t *data_len,
  hsk_checkpoint_t *checkpoint
);

bool
hsk_store_write(hsk_checkpoint_t *checkpoint, char *prefix);

bool
hsk_store_read(hsk_checkpoint_t *checkpoint, char *prefix);

#endif
