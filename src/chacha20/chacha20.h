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

#ifndef _HSK_CHACHA20_H
#define _HSK_CHACHA20_H

#include <stdint.h>

typedef struct {
  uint32_t schedule[16];
  uint32_t keystream[16];
  size_t available;
  uint8_t nonce_size;
} hsk_chacha20_ctx;

void
hsk_chacha20_setup(
  hsk_chacha20_ctx *ctx,
  const uint8_t *key,
  size_t length,
  const uint8_t *nonce,
  uint8_t nonce_size
);

void
hsk_chacha20_keysetup(hsk_chacha20_ctx *ctx, const uint8_t *key, size_t length);

void
hsk_chacha20_ivsetup(
  hsk_chacha20_ctx *ctx,
  const uint8_t *nonce,
  uint8_t nonce_size
);

void
hsk_chacha20_counter_set(hsk_chacha20_ctx *ctx, uint64_t counter);

void
hsk_chacha20_block(hsk_chacha20_ctx *ctx, uint32_t output[16]);

void
hsk_chacha20_encrypt(
  hsk_chacha20_ctx *ctx,
  const uint8_t *in,
  uint8_t *out,
  size_t length
);

void
hsk_chacha20_decrypt(
  hsk_chacha20_ctx *ctx,
  const uint8_t *in,
  uint8_t *out,
  size_t length
);

uint64_t hsk_chacha20_counter_get(hsk_chacha20_ctx *ctx);

#endif
