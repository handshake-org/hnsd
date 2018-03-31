/**
 * Parts of this software are based on RHash:
 * https://github.com/rhash/RHash
 *
 * Copyright: 2010-2012 Aleksey Kravchenko <rhash.admin@gmail.com>
 *
 * Permission is hereby granted,  free of charge,  to any person  obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction,  including without limitation
 * the rights to  use, copy, modify,  merge, publish, distribute, sublicense,
 * and/or sell copies  of  the Software,  and to permit  persons  to whom the
 * Software is furnished to do so.
 *
 * This program  is  distributed  in  the  hope  that it will be useful,  but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  Use this program  at  your own risk!
 */

#include "config.h"

#include <string.h>

#include "sha256.h"

static inline uint32_t
bswap_32(uint32_t x) {
  x = ((x << 8) & 0xFF00FF00u) | ((x >> 8) & 0x00FF00FFu);
  return (x >> 16) | (x << 16);
}

static void
swap_copy_str_to_u32(void *to, int index, const void *from, size_t length) {
  // if all pointers and length are 32-bits aligned
  if (0 == (((int)((char *)to - (char *)0)
      | ((char *)from - (char *)0) | index | length) & 3)) {
    // copy memory as 32-bit words
    const uint32_t *src = (const uint32_t *)from;
    const uint32_t *end = (const uint32_t *)((const char *)src + length);
    uint32_t *dst = (uint32_t *)((char *)to + index);
    for (; src < end; dst++, src++)
      *dst = bswap_32(*src);
  } else {
    const char *src = (const char *)from;
    for (length += index; (size_t)index < length; index++)
      ((char *)to)[index ^ 3] = *(src++);
  }
}

#define IS_ALIGNED_32(p) (0 == (3 & ((const char*)(p) - (const char*)0)))

#ifdef HSK_BIG_ENDIAN
#define be2me_32(x) (x)
#define le2me_32(x) bswap_32(x)
#define be32_copy(to, index, from, length) \
  memcpy((to) + (index), (from), (length))
#else
#define be2me_32(x) bswap_32(x)
#define le2me_32(x) (x)
#define be32_copy(to, index, from, length) \
  swap_copy_str_to_u32((to), (index), (from), (length))
#endif

#define ROTR32(dword, n) ((dword) >> (n) ^ ((dword) << (32 - (n))))

static const unsigned int k256[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define Ch(x, y, z)  ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x, y, z) (((x) & (y)) ^ ((z) & ((x) ^ (y))))

#define Sigma0(x) (ROTR32((x), 2) ^ ROTR32((x), 13) ^ ROTR32((x), 22))
#define Sigma1(x) (ROTR32((x), 6) ^ ROTR32((x), 11) ^ ROTR32((x), 25))
#define sigma0(x) (ROTR32((x), 7) ^ ROTR32((x), 18) ^ ((x) >>  3))
#define sigma1(x) (ROTR32((x),17) ^ ROTR32((x), 19) ^ ((x) >> 10))

#define RECALCULATE_W(W,n) (W[n] += \
  (sigma1(W[(n - 2) & 15])          \
   + W[(n - 7) & 15]                \
   + sigma0(W[(n - 15) & 15])))

#define ROUND(a, b, c, d, e, f, g, h, k, data) {              \
  unsigned int T1 = h + Sigma1(e) + Ch(e, f, g) + k + (data); \
  d += T1;                                                    \
  h = T1 + Sigma0(a) + Maj(a, b, c);                          \
}

#define ROUND_1_16(a, b, c, d, e, f, g, h, n)                       \
  ROUND(a, b, c, d, e, f, g, h, k256[n], W[n] = be2me_32(block[n]))

#define ROUND_17_64(a, b, c, d, e, f, g, h, n)             \
  ROUND(a, b, c, d, e, f, g, h, k[n], RECALCULATE_W(W, n))

void
hsk_sha256_init(hsk_sha256_ctx *ctx) {
  // Initial values. These words were obtained by taking the first 32
  // bits of the fractional parts of the square roots of the first
  // eight prime numbers.
  static const unsigned int HSK_SHA_256_H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  };

  ctx->length = 0;
  ctx->digest_length = hsk_sha256_hash_size;

  // initialize algorithm state
  memcpy(ctx->hash, HSK_SHA_256_H0, sizeof(ctx->hash));
}

static void
hsk_sha256_process_block(unsigned hash[8], unsigned block[16]) {
  unsigned int A, B, C, D, E, F, G, H;
  unsigned int W[16];
  const unsigned int *k;
  int i;

  A = hash[0], B = hash[1], C = hash[2], D = hash[3];
  E = hash[4], F = hash[5], G = hash[6], H = hash[7];

  // Compute SHA using alternate Method: FIPS 180-3 6.1.3
  ROUND_1_16(A, B, C, D, E, F, G, H, 0);
  ROUND_1_16(H, A, B, C, D, E, F, G, 1);
  ROUND_1_16(G, H, A, B, C, D, E, F, 2);
  ROUND_1_16(F, G, H, A, B, C, D, E, 3);
  ROUND_1_16(E, F, G, H, A, B, C, D, 4);
  ROUND_1_16(D, E, F, G, H, A, B, C, 5);
  ROUND_1_16(C, D, E, F, G, H, A, B, 6);
  ROUND_1_16(B, C, D, E, F, G, H, A, 7);
  ROUND_1_16(A, B, C, D, E, F, G, H, 8);
  ROUND_1_16(H, A, B, C, D, E, F, G, 9);
  ROUND_1_16(G, H, A, B, C, D, E, F, 10);
  ROUND_1_16(F, G, H, A, B, C, D, E, 11);
  ROUND_1_16(E, F, G, H, A, B, C, D, 12);
  ROUND_1_16(D, E, F, G, H, A, B, C, 13);
  ROUND_1_16(C, D, E, F, G, H, A, B, 14);
  ROUND_1_16(B, C, D, E, F, G, H, A, 15);

  for (i = 16, k = &k256[16]; i < 64; i += 16, k += 16) {
    ROUND_17_64(A, B, C, D, E, F, G, H,  0);
    ROUND_17_64(H, A, B, C, D, E, F, G,  1);
    ROUND_17_64(G, H, A, B, C, D, E, F,  2);
    ROUND_17_64(F, G, H, A, B, C, D, E,  3);
    ROUND_17_64(E, F, G, H, A, B, C, D,  4);
    ROUND_17_64(D, E, F, G, H, A, B, C,  5);
    ROUND_17_64(C, D, E, F, G, H, A, B,  6);
    ROUND_17_64(B, C, D, E, F, G, H, A,  7);
    ROUND_17_64(A, B, C, D, E, F, G, H,  8);
    ROUND_17_64(H, A, B, C, D, E, F, G,  9);
    ROUND_17_64(G, H, A, B, C, D, E, F, 10);
    ROUND_17_64(F, G, H, A, B, C, D, E, 11);
    ROUND_17_64(E, F, G, H, A, B, C, D, 12);
    ROUND_17_64(D, E, F, G, H, A, B, C, 13);
    ROUND_17_64(C, D, E, F, G, H, A, B, 14);
    ROUND_17_64(B, C, D, E, F, G, H, A, 15);
  }

  hash[0] += A, hash[1] += B, hash[2] += C, hash[3] += D;
  hash[4] += E, hash[5] += F, hash[6] += G, hash[7] += H;
}

void
hsk_sha256_update(hsk_sha256_ctx *ctx, const unsigned char *msg, size_t size) {
  size_t index = (size_t)ctx->length & 63;
  ctx->length += size;

  // fill partial block
  if (index) {
    size_t left = hsk_sha256_block_size - index;
    memcpy((char *)ctx->message + index, msg, (size < left ? size : left));

    if (size < left)
      return;

    // process partial block
    hsk_sha256_process_block(ctx->hash, (unsigned *)ctx->message);
    msg += left;
    size -= left;
  }

  while (size >= hsk_sha256_block_size) {
    unsigned int *aligned_message_block;

    if (IS_ALIGNED_32(msg)) {
      // the most common case is processing of an
      // already aligned message without copying it
      aligned_message_block = (unsigned int *)msg;
    } else {
      memcpy(ctx->message, msg, hsk_sha256_block_size);
      aligned_message_block = (unsigned int *)ctx->message;
    }

    hsk_sha256_process_block(ctx->hash, aligned_message_block);

    msg += hsk_sha256_block_size;
    size -= hsk_sha256_block_size;
  }

  // save leftovers
  if (size)
    memcpy(ctx->message, msg, size);
}

void
hsk_sha256_final(hsk_sha256_ctx *ctx, unsigned char *result) {
  size_t index = ((unsigned int)ctx->length & 63) >> 2;
  unsigned int shift = ((unsigned int)ctx->length & 3) * 8;

  // append the byte 0x80 to the message
  ctx->message[index] &= le2me_32(~(0xFFFFFFFFu << shift));
  ctx->message[index++] ^= le2me_32(0x80u << shift);

  // if no room left in the message
  // to store 64-bit message length
  if (index > 14) {
    // then fill the rest with
    // zeros and process it
    while (index < 16)
      ctx->message[index++] = 0;

    hsk_sha256_process_block(ctx->hash, ctx->message);
    index = 0;
  }

  while (index < 14)
    ctx->message[index++] = 0;

  ctx->message[14] = be2me_32((unsigned int)(ctx->length >> 29));
  ctx->message[15] = be2me_32((unsigned int)(ctx->length << 3));
  hsk_sha256_process_block(ctx->hash, ctx->message);

  if (result)
    be32_copy(result, 0, ctx->hash, ctx->digest_length);
}
