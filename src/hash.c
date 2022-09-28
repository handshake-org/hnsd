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
hsk_hash_blake2b_key(
  const uint8_t *data,
  size_t data_len,
  const uint8_t *key,
  size_t key_len,
  uint8_t *hash
) {
  assert(hash != NULL);
  hsk_blake2b_ctx ctx;
  assert(hsk_blake2b_init_key(&ctx, 32, key, key_len) == 0);
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
hsk_hash_blake256(const uint8_t *data, size_t data_len, uint8_t *hash) {
  assert(hash != NULL);
  hsk_blake2b_ctx ctx;
  assert(hsk_blake2b_init(&ctx, 32) == 0);
  hsk_blake2b_update(&ctx, data, data_len);
  assert(hsk_blake2b_final(&ctx, hash, 32) == 0);
}

void
hsk_hash_blake512(const uint8_t *data, size_t data_len, uint8_t *hash) {
  assert(hash != NULL);
  hsk_blake2b_ctx ctx;
  assert(hsk_blake2b_init(&ctx, 64) == 0);
  hsk_blake2b_update(&ctx, data, data_len);
  assert(hsk_blake2b_final(&ctx, hash, 64) == 0);
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
hsk_hash_sha3_key(
  const uint8_t *data,
  size_t data_len,
  const uint8_t *key,
  size_t key_len,
  uint8_t *hash
) {
  assert(hash != NULL);
  assert(data_len == 208);
  assert(key_len == 32);

  hsk_sha3_ctx ctx;
  hsk_sha3_256_init(&ctx);

  uint8_t mac[483];

  // leftEncode(rate / 8) 2,0 "0188"
  mac[0] = 0x01;
  mac[1] = 0x88;

  // leftEncode(name.length * 8) 2,2 "0120"
  mac[2] = 0x01;
  mac[3] = 0x20;

  // encodeString(name = "KMAC") 4,4 "4b4d4143"
  mac[4] = 0x4b;
  mac[5] = 0x4d;
  mac[6] = 0x41;
  mac[7] = 0x43;

  // leftEncode(pers.length * 8) 2,8 "0100"
  mac[8] = 0x01;
  mac[9] = 0x00;

  // encodeString(pers = "") 0,10 ""
  memset(&mac[10], 0x00, 0);

  // zeroPad(126) 126,10 "00..."
  memset(&mac[10], 0x00, 126);

  // leftEncode(rate / 8) 2,136 "0188"
  mac[136] = 0x01;
  mac[137] = 0x88;

  // leftEncode(key.length * 8) 3,138 "020100"
  mac[138] = 0x02;
  mac[139] = 0x01;
  mac[140] = 0x00;

  // encodeString(key = nonce) 32,141 "..."
  memcpy(&mac[141], &key[0], 32);

  // zeroPad(99) 99,173 "00..."
  memset(&mac[173], 0x00, 99);

  // update(hdr) 208,272 "..."
  memcpy(&mac[272], &data[0], 208);

  // rightEncode(output_len * 8) 3,480 "010002"
  mac[480] = 0x01;
  mac[481] = 0x00;
  mac[482] = 0x02;

  hsk_sha3_update(&ctx, mac, 483);
  hsk_cshake_final(&ctx, hash);
}

void
hsk_hash_tld(const uint8_t *tld, uint8_t *hash) {
  assert(tld && hash);
  // First byte is length
  hsk_hash_sha3(&tld[1], tld[0], hash);
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
