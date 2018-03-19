#ifndef _HSK_HASH_H
#define _HSK_HASH_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

void
hsk_hash_blake2b(uint8_t *data, size_t data_len, uint8_t *hash);

void
hsk_hash_sha256(uint8_t *data, size_t data_len, uint8_t *hash);

void
hsk_hash_hash256(uint8_t *data, size_t data_len, uint8_t *hash);

void
hsk_hash_sha256_hmac(
  uint8_t *data,
  size_t data_len,
  uint8_t *key,
  size_t key_len,
  uint8_t *mac
);

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
);
#endif
