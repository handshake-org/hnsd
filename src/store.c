#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "bio.h"
#include "error.h"
#include "header.h"
#include "store.h"

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
