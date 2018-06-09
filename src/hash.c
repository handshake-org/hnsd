#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "blake2b.h"
#include "hash.h"
#include "sha256.h"
#include "sha3.h"
#include "utils.h"

void
hsk_hash_blake2b(const uint8_t *data, size_t data_len, uint8_t *hash) {
  assert(hash != NULL);
  hsk_blake2b_ctx ctx;
  assert(hsk_blake2b_init(&ctx, 32) == 0);
  hsk_blake2b_update(&ctx, data, data_len);
  assert(hsk_blake2b_final(&ctx, hash, 32) == 0);
}

void
hsk_hash_blake160(const uint8_t *data, size_t data_len, uint8_t *hash) {
  assert(hash != NULL);
  hsk_blake2b_ctx ctx;
  assert(hsk_blake2b_init(&ctx, 20) == 0);
  hsk_blake2b_update(&ctx, data, data_len);
  assert(hsk_blake2b_final(&ctx, hash, 20) == 0);
}

void
hsk_hash_sha3(const uint8_t *data, size_t data_len, uint8_t *hash) {
  assert(hash != NULL);
  hsk_sha3_ctx ctx;
  hsk_sha3_256_init(&ctx);
  hsk_sha3_update(&ctx, data, data_len);
  hsk_sha3_final(&ctx, hash);
}

void
hsk_hash_name(const char *name, uint8_t *hash) {
  assert(name && hash);
  hsk_hash_sha3((uint8_t *)name, strlen(name), hash);
}

void
hsk_hash_sha256(const uint8_t *data, size_t data_len, uint8_t *hash) {
  assert(hash != NULL);
  hsk_sha256_ctx ctx;
  hsk_sha256_init(&ctx);
  hsk_sha256_update(&ctx, data, data_len);
  hsk_sha256_final(&ctx, hash);
}

void
hsk_hash_hash256(const uint8_t *data, size_t data_len, uint8_t *hash) {
  assert(hash != NULL);
  hsk_sha256_ctx ctx;
  hsk_sha256_init(&ctx);
  hsk_sha256_update(&ctx, data, data_len);
  hsk_sha256_final(&ctx, hash);
  hsk_sha256_init(&ctx);
  hsk_sha256_update(&ctx, hash, 32);
  hsk_sha256_final(&ctx, hash);
}

void
hsk_hash_sha256_hmac(
  const uint8_t *data,
  size_t data_len,
  const uint8_t *key,
  size_t key_len,
  uint8_t *mac
) {
  // Initializing.
  hsk_sha256_ctx inner;
  hsk_sha256_ctx outer;

  uint8_t k[32];
  uint8_t pad[64];

  if (key_len > 64) {
    hsk_hash_sha256(key, key_len, k);
    key = &k[0];
    key_len = 32;
  }

  int i;

  for (i = 0; i < key_len; i++)
    pad[i] = key[i] ^ 0x36;

  for (i = key_len; i < 64; i++)
    pad[i] = 0x36;

  hsk_sha256_init(&inner);
  hsk_sha256_update(&inner, pad, 64);

  for (i = 0; i < key_len; i++)
    pad[i] = key[i] ^ 0x5c;

  for (i = key_len; i < 64; i++)
    pad[i] = 0x5c;

  hsk_sha256_init(&outer);
  hsk_sha256_update(&outer, pad, 64);

  // Updating
  hsk_sha256_update(&inner, data, data_len);

  // Finalizing
  hsk_sha256_final(&inner, mac);
  hsk_sha256_update(&outer, mac, 32);
  hsk_sha256_final(&outer, mac);
}

void
hsk_hash_hkdf(
  const uint8_t *secret,
  size_t secret_len,
  const uint8_t *salt,
  size_t salt_len,
  const uint8_t *info,
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

  int i = 1;
  for (; i < 2; i++) {
    memcpy(buf, out, 32);
    buf[buf_len - 1] += 1;
    hsk_hash_sha256_hmac(buf, buf_len, prk, 32, out);
    memcpy(&okm[i * 32], out, 32);
  }

  memcpy(h1, &okm[0], 32);
  memcpy(h2, &okm[32], 32);
}
