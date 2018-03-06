#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "bio.h"
#include "hsk-hash.h"
#include "blake2b.h"
#include "sha256.h"
#include "chacha20/chacha20.h"
#include "poly1305/poly1305-donna.h"
#include "hsk-aead.h"

void
hsk_aead_init(hsk_aead_t *aead) {
  memset(&aead->chacha, 0, sizeof(chacha20_ctx));
  memset(&aead->poly, 0, sizeof(poly1305_context));
  aead->aad_len = 0;
  aead->cipher_len = 0;
  aead->has_cipher = false;
  memset(aead->poly_key, 0, 32);
}

void
hsk_aead_start(hsk_aead_t *aead, uint8_t *key, uint8_t *iv) {
  memset(aead->poly_key, 0, 32);

  if (key)
    chacha20_keysetup(&aead->chacha, key, 32);

  if (iv) {
    chacha20_ivsetup(&aead->chacha, iv, 12);
    chacha20_counter_set(&aead->chacha, 0);
  }

  chacha20_encrypt(&aead->chacha, aead->poly_key, aead->poly_key, 32);

  poly1305_init(&aead->poly, aead->poly_key);

  uint8_t half_block[32];
  memset(half_block, 0, 32);

  chacha20_encrypt(&aead->chacha, half_block, half_block, 32);

  assert(chacha20_counter_get(&aead->chacha) == 1);

  aead->aad_len = 0;
  aead->cipher_len = 0;
  aead->has_cipher = false;
}

void
hsk_aead_aad(hsk_aead_t *aead, uint8_t *aad, size_t len) {
  // assert(!aead->has_cipher);
  assert(aead->cipher_len == 0);
  poly1305_update(&aead->poly, aad, len);
  aead->aad_len += len;
}

void
hsk_aead_encrypt(hsk_aead_t *aead, uint8_t *in, uint8_t *out, size_t len) {
  // if (!aead->has_cipher)
  if (aead->cipher_len == 0)
    hsk_aead_pad16(aead, aead->aad_len);

  chacha20_encrypt(&aead->chacha, in, out, len);
  poly1305_update(&aead->poly, out, len);

  aead->cipher_len += len;
  aead->has_cipher = true;
}

void
hsk_aead_decrypt(hsk_aead_t *aead, uint8_t *in, uint8_t *out, size_t len) {
  // if (!aead->has_cipher)
  if (aead->cipher_len == 0)
    hsk_aead_pad16(aead, aead->aad_len);

  aead->cipher_len += len;
  aead->has_cipher = true;

  poly1305_update(&aead->poly, in, len);
  chacha20_encrypt(&aead->chacha, in, out, len);
}

void
hsk_aead_auth(hsk_aead_t *aead, uint8_t *in, size_t len) {
  // if (!aead->has_cipher)
  if (aead->cipher_len == 0)
    hsk_aead_pad16(aead, aead->aad_len);

  aead->cipher_len += len;
  aead->has_cipher = true;

  poly1305_update(&aead->poly, in, len);
}

void
hsk_aead_final(hsk_aead_t *aead, uint8_t *tag) {
  uint8_t len[16];
  uint8_t *buf = &len[0];

  write_u64(&buf, aead->aad_len);
  write_u64(&buf, aead->cipher_len);

  // if (!aead->has_cipher)
  if (aead->cipher_len == 0)
    hsk_aead_pad16(aead, aead->aad_len);

  hsk_aead_pad16(aead, aead->cipher_len);
  poly1305_update(&aead->poly, len, 16);

  poly1305_finish(&aead->poly, tag);
}

void
hsk_aead_pad16(hsk_aead_t *aead, size_t size) {
  size %= 16;

  if (size == 0)
    return;

  uint8_t pad[16];
  memset(pad, 0, 16);

  poly1305_update(&aead->poly, pad, 16 - size);
}

bool
hsk_aead_verify(uint8_t *mac1, uint8_t *mac2) {
  return poly1305_verify(mac1, mac2) != 0;
}
