
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include "bio.h"
#include "chain.h"
#include "header.h"
#include "store.h"

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
