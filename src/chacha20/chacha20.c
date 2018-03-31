/**
 * Parts of this software are based on chacha20-simple:
 * http://chacha20.insanecoding.org/
 *
 *   Copyright (C) 2014 insane coder
 *
 *   Permission to use, copy, modify, and distribute this software for any
 *   purpose with or without fee is hereby granted, provided that the above
 *   copyright notice and this permission notice appear in all copies.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 *   SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 *   IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   This implementation is intended to be simple, many optimizations can be
 *   performed.
 */

#include "config.h"

#include <string.h>

#include "chacha20.h"

#define ROTL32(v, n) ((v) << (n)) | ((v) >> (32 - (n)))

#define READLE(p)                   \
  (((uint32_t)((p)[0]))         \
  | ((uint32_t)((p)[1]) << 8)   \
  | ((uint32_t)((p)[2]) << 16)  \
  | ((uint32_t)((p)[3]) << 24))

#define WRITELE(b, i)         \
  (b)[0] = i & 0xFF;         \
  (b)[1] = (i >> 8) & 0xFF;  \
  (b)[2] = (i >> 16) & 0xFF; \
  (b)[3] = (i >> 24) & 0xFF;

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define QUARTERROUND(x, a, b, c, d)             \
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 16); \
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 12); \
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 8);  \
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 7);

void
hsk_chacha20_setup(
  hsk_chacha20_ctx *ctx,
  const uint8_t *key,
  size_t length,
  uint8_t *nonce,
  uint8_t iv_size
) {
  hsk_chacha20_keysetup(ctx, key, length);
  hsk_chacha20_ivsetup(ctx, nonce, iv_size);
}

void
hsk_chacha20_keysetup(
  hsk_chacha20_ctx *ctx,
  const uint8_t *key,
  size_t length
) {
  const char *constants = (length == 32)
    ? "expand 32-byte k"
    : "expand 16-byte k";

  ctx->schedule[0] = READLE(constants + 0);
  ctx->schedule[1] = READLE(constants + 4);
  ctx->schedule[2] = READLE(constants + 8);
  ctx->schedule[3] = READLE(constants + 12);
  ctx->schedule[4] = READLE(key + 0);
  ctx->schedule[5] = READLE(key + 4);
  ctx->schedule[6] = READLE(key + 8);
  ctx->schedule[7] = READLE(key + 12);
  ctx->schedule[8] = READLE(key + 16 % length);
  ctx->schedule[9] = READLE(key + 20 % length);
  ctx->schedule[10] = READLE(key + 24 % length);
  ctx->schedule[11] = READLE(key + 28 % length);
  ctx->schedule[12] = 0;

  ctx->available = 0;
  ctx->iv_size = 8;
}

void
hsk_chacha20_ivsetup(hsk_chacha20_ctx *ctx, uint8_t *nonce, uint8_t iv_size) {
  ctx->schedule[12] = 0;

  if (iv_size == 8) {
    ctx->schedule[13] = 0;
    ctx->schedule[14] = READLE(nonce + 0);
    ctx->schedule[15] = READLE(nonce + 4);
  } else {
    ctx->schedule[13] = READLE(nonce + 0);
    ctx->schedule[14] = READLE(nonce + 4);
    ctx->schedule[15] = READLE(nonce + 8);
  }

  ctx->iv_size = iv_size;
}

void
hsk_chacha20_counter_set(hsk_chacha20_ctx *ctx, uint64_t counter) {
  if (ctx->iv_size == 8) {
    ctx->schedule[12] = counter & UINT32_C(0xFFFFFFFF);
    ctx->schedule[13] = counter >> 32;
  } else {
    ctx->schedule[12] = (uint32_t)counter;
  }
  ctx->available = 0;
}

uint64_t
hsk_chacha20_counter_get(hsk_chacha20_ctx *ctx) {
  if (ctx->iv_size == 8)
    return ((uint64_t)ctx->schedule[13] << 32) | ctx->schedule[12];

  return (uint64_t)ctx->schedule[12];
}

void
hsk_chacha20_block(hsk_chacha20_ctx *ctx, uint32_t output[16]) {
  uint32_t *nonce = ctx->schedule + 12;
  int i = 10;

  memcpy(output, ctx->schedule, sizeof(ctx->schedule));

  while (i--) {
    QUARTERROUND(output, 0, 4, 8, 12)
    QUARTERROUND(output, 1, 5, 9, 13)
    QUARTERROUND(output, 2, 6, 10, 14)
    QUARTERROUND(output, 3, 7, 11, 15)
    QUARTERROUND(output, 0, 5, 10, 15)
    QUARTERROUND(output, 1, 6, 11, 12)
    QUARTERROUND(output, 2, 7, 8, 13)
    QUARTERROUND(output, 3, 4, 9, 14)
  }

  for (i = 0; i < 16; i++) {
    uint32_t result = output[i] + ctx->schedule[i];
    WRITELE((uint8_t *)(output + i), result);
  }

  if (!++nonce[0]) {
    if (ctx->iv_size == 8)
      nonce[1]++;
  }
}

static inline
void hsk_chacha20_xor(
  uint8_t *keystream,
  const uint8_t **in,
  uint8_t **out,
  size_t length
) {
  uint8_t *end_keystream = keystream + length;
  do {
    *(*out)++ = *(*in)++ ^ *keystream++;
  } while (keystream < end_keystream);
}

void
hsk_chacha20_encrypt(
  hsk_chacha20_ctx *ctx,
  const uint8_t *in,
  uint8_t *out,
  size_t length
) {
  if (length) {
    uint8_t *k = (uint8_t *)ctx->keystream;

    if (ctx->available) {
      size_t amount = MIN(length, ctx->available);
      size_t size = sizeof(ctx->keystream) - ctx->available;
      hsk_chacha20_xor(k + size, &in, &out, amount);
      ctx->available -= amount;
      length -= amount;
    }

    while (length) {
      size_t amount = MIN(length, sizeof(ctx->keystream));
      hsk_chacha20_block(ctx, ctx->keystream);
      hsk_chacha20_xor(k, &in, &out, amount);
      length -= amount;
      ctx->available = sizeof(ctx->keystream) - amount;
    }
  }
}

void
hsk_chacha20_decrypt(
  hsk_chacha20_ctx *ctx,
  const uint8_t *in,
  uint8_t *out,
  size_t length
) {
  hsk_chacha20_encrypt(ctx, in, out, length);
}
