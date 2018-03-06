#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

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

void
hsk_hash_sha256_hmac(
  uint8_t *data,
  size_t data_len,
  uint8_t *key,
  size_t key_len,
  uint8_t *mac
) {
  // Initializing.
  sha256_ctx inner;
  sha256_init(&inner);

  sha256_ctx outer;
  sha256_init(&outer);

  uint8_t k[32];
  uint8_t pad[32];

  if (key_len > 32) {
    hsk_hash_sha256(key, key_len, k);
    key = &k[0];
    key_len = 32;
  }

  int32_t i;

  for (i = 0; i < key_len; i++)
    pad[i] = key[i] ^ 0x36;

  for (i = key_len; i < 32; i++)
    pad[i] = 0x36;

  sha256_update(&inner, pad, 32);

  for (i = 0; i < key_len; i++)
    pad[i] = key[i] ^ 0x5c;

  for (i = key_len; i < 32; i++)
    pad[i] = 0x5c;

  sha256_update(&outer, pad, 32);

  // Updating
  sha256_update(&inner, data, data_len);

  // Finalizing
  sha256_final(&inner, mac);
  sha256_update(&outer, mac, 32);
  sha256_final(&outer, mac);
}

void
hsk_hash_hkdf(
  uint8_t *secret,
  size_t secret_len,
  uint8_t *salt,
  size_t salt_len,
  uint8_t *info,
  size_t info_len,
  uint8_t *h1,
  uint8_t *h2
) {
  assert(info_len <= 512);

  // EXTRACT(ikm=secret, key=salt)
  uint8_t prk[32];
  hsk_hash_sha256_hmac(secret, secret_len, salt, salt_len, prk);

  // EXPAND(prk, info=info, 64)
  uint8_t okm[64];
  size_t buf_len = 32 + info_len + 1;
  uint8_t buf[buf_len];

  // First round:
  memcpy(&buf[32], info, info_len);
  buf[buf_len - 1] = 1;

  // First block.
  uint8_t out[32];
  hsk_hash_sha256_hmac(&buf[32], buf_len - 32, prk, 32, out);
  memcpy(&okm[0], out, 32);

  int32_t i = 1;
  for (; i < 2; i++) {
    memcpy(buf, out, 32);
    buf[buf_len - 1] += 1;
    hsk_hash_sha256_hmac(buf, buf_len, prk, 32, out);
    memcpy(&okm[i * 32], out, 32);
  }

  memcpy(h1, &okm[0], 32);
  memcpy(h2, &okm[32], 32);
}
