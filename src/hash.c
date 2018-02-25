#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "hsk-hash.h"
#include "blake2b.h"
#include "sha256.h"

int32_t
hsk_hash_blake2b(uint8_t *data, size_t data_len, uint8_t *hash) {
  assert(hash != NULL);
  blake2b_ctx ctx;
  assert(blake2b_init(&ctx, 32) == 0);
  blake2b_update(&ctx, data, data_len);
  return blake2b_final(&ctx, hash, 32);
}

void
hsk_hash_sha256(uint8_t *data, size_t data_len, uint8_t *hash) {
  assert(hash != NULL);
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, data_len);
  sha256_final(&ctx, hash);
}

void
hsk_hash_hash256(uint8_t *data, size_t data_len, uint8_t *hash) {
  assert(hash != NULL);
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, data_len);
  sha256_final(&ctx, hash);
  sha256_init(&ctx);
  sha256_update(&ctx, hash, 32);
  sha256_final(&ctx, hash);
}
