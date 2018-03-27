#ifndef _HSK_AEAD_H
#define _HSK_AEAD_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "chacha20/chacha20.h"
#include "poly1305/poly1305-donna.h"

typedef struct hsk_aead_s {
  hsk_chacha20_ctx chacha;
  hsk_poly1305_ctx poly;
  size_t aad_len;
  size_t cipher_len;
  bool has_cipher;
  uint8_t poly_key[32];
} hsk_aead_t;

void
hsk_aead_init(hsk_aead_t *aead);

void
hsk_aead_setup(hsk_aead_t *aead, uint8_t *key, uint8_t *iv);

void
hsk_aead_aad(hsk_aead_t *aead, uint8_t *aad, size_t len);

void
hsk_aead_encrypt(hsk_aead_t *aead, uint8_t *in, uint8_t *out, size_t len);

void
hsk_aead_decrypt(hsk_aead_t *aead, uint8_t *in, uint8_t *out, size_t len);

void
hsk_aead_auth(hsk_aead_t *aead, uint8_t *in, size_t len);

void
hsk_aead_final(hsk_aead_t *aead, uint8_t *tag);

void
hsk_aead_pad16(hsk_aead_t *aead, size_t size);

bool
hsk_aead_verify(uint8_t *mac1, uint8_t *mac2);
#endif
