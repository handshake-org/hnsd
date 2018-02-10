#include <assert.h>
#include <stdint.h>

#include "blake2b.h"

int32_t
hsk_blake2b(uint8_t *data, size_t data_len, uint8_t *hash) {
  assert(hash != NULL);
  blake2b_ctx ctx;
  assert(blake2b_init(&ctx, 32) == 0);
  blake2b_update(&ctx, data, data_len);
  return blake2b_final(&ctx, hash, 32);
}
