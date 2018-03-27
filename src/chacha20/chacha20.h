/*
Copyright (C) 2014 insane coder (http://insanecoding.blogspot.com/, http://chacha20.insanecoding.org/)

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#ifndef HSK_CHACHA20_SIMPLE_H
#define HSK_CHACHA20_SIMPLE_H
#include <stdint.h>

#define ROTL32(v, n) ((v) << (n)) | ((v) >> (32 - (n)))

#define LE(p) (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))
#define FROMLE(b, i) (b)[0] = i & 0xFF; (b)[1] = (i >> 8) & 0xFF; (b)[2] = (i >> 16) & 0xFF; (b)[3] = (i >> 24) & 0xFF;

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
  uint32_t schedule[16];
  uint32_t keystream[16];
  size_t available;
  uint8_t iv_size;
} hsk_chacha20_ctx;

//Call this to initilize a hsk_chacha20_ctx, must be called before all other functions
void hsk_chacha20_setup(hsk_chacha20_ctx *ctx, const uint8_t *key, size_t length, uint8_t *nonce, uint8_t iv_size);

void hsk_chacha20_keysetup(hsk_chacha20_ctx *ctx, const uint8_t *key, size_t length);

void hsk_chacha20_ivsetup(hsk_chacha20_ctx *ctx, uint8_t *nonce, uint8_t iv_size);

//Call this if you need to process a particular block number
void hsk_chacha20_counter_set(hsk_chacha20_ctx *ctx, uint64_t counter);

//Raw keystream for the current block, convert output to uint8_t[] for individual bytes. Counter is incremented upon use
void hsk_chacha20_block(hsk_chacha20_ctx *ctx, uint32_t output[16]);

//Encrypt an arbitrary amount of plaintext, call continuously as needed
void hsk_chacha20_encrypt(hsk_chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, size_t length);

//Decrypt an arbitrary amount of ciphertext. Actually, for chacha20, decryption is the same function as encryption
void hsk_chacha20_decrypt(hsk_chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, size_t length);

uint64_t hsk_chacha20_counter_get(hsk_chacha20_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif
