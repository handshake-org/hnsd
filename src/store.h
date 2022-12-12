#ifndef _HSK_STORE
#define _HSK_STORE

#include "chain.h"

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
#define HSK_STORE_FILENAME "checkpoint"
#define HSK_STORE_EXTENSION ".dat"
#define HSK_STORE_PATH_RESERVED 32
#define HSK_STORE_PATH_MAX 1024

/*
 * Store
 */

bool
hsk_store_exists(char *path);

void
hsk_store_write(const hsk_chain_t *chain);

bool
hsk_store_inject_checkpoint(
  uint8_t **data,
  size_t *data_len,
  hsk_chain_t *chain
);

bool
hsk_store_read(
  uint8_t **data,
  size_t *data_len,
  hsk_chain_t *chain
);

#endif
