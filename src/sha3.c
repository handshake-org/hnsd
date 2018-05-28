/* sha3.c - an implementation of Secure Hash Algorithm 3 (Keccak).
 * based on the
 * The Keccak SHA-3 submission. Submission to NIST (Round 3), 2011
 * by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche
 *
 * Copyright: 2013 Aleksey Kravchenko <rhash.admin@gmail.com>
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

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include "sha3.h"

#define HSK_SHA3_ROUNDS 24
#define HSK_SHA3_FINALIZED 0x80000000

#if defined(i386) || defined(__i386__) || defined(__i486__) \
  || defined(__i586__) || defined(__i686__) || defined(__pentium__) \
  || defined(__pentiumpro__) || defined(__pentium4__) \
  || defined(__nocona__) || defined(prescott) || defined(__core2__) \
  || defined(__k6__) || defined(__k8__) || defined(__athlon__) \
  || defined(__amd64) || defined(__amd64__) \
  || defined(__x86_64) || defined(__x86_64__) || defined(_M_IX86) \
  || defined(_M_AMD64) || defined(_M_IA64) || defined(_M_X64)
#if defined(_LP64) || defined(__LP64__) || defined(__x86_64) \
  || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
#define CPU_X64
#else
#define CPU_IA32
#endif
#endif

#define ROTL64(qword, n) ((qword) << (n) ^ ((qword) >> (64 - (n))))

#if defined(_MSC_VER) || defined(__BORLANDC__)
#define I64(x) x##ui64
#else
#define I64(x) x##ULL
#endif

#define IS_ALIGNED_64(p) (0 == (7 & ((const char *)(p) - (const char *)0)))

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#if (defined(__GNUC__) \
      && (__GNUC__ >= 4) \
      && (__GNUC__ > 4 || __GNUC_MINOR__ >= 3)) \
    || (defined(__clang__) \
    && __has_builtin(__builtin_bswap32) \
    && __has_builtin(__builtin_bswap64))
#define bswap_32(x) __builtin_bswap32(x)
#define bswap_64(x) __builtin_bswap64(x)
#elif (_MSC_VER > 1300) && (defined(CPU_IA32) || defined(CPU_X64))
#define bswap_32(x) _byteswap_ulong((unsigned long)x)
#define bswap_64(x) _byteswap_uint64((__int64)x)
#else
static inline uint32_t
bswap_32(uint32_t x)
{
#if defined(__GNUC__) && defined(CPU_IA32) && !defined(__i386__)
  __asm("bswap\t%0" : "=r" (x) : "0" (x));
  return x;
#else
  x = ((x << 8) & 0xFF00FF00u) | ((x >> 8) & 0x00FF00FFu);
  return (x >> 16) | (x << 16);
#endif
}

static inline uint64_t
bswap_64(uint64_t x) {
  union {
    uint64_t ll;
    uint32_t l[2];
  } w, r;
  w.ll = x;
  r.l[0] = bswap_32(w.l[1]);
  r.l[1] = bswap_32(w.l[0]);
  return r.ll;
}
#endif

static void
swap_copy_u64_to_str(void *t, const void *f, size_t l) {
  if (0 == (((int)((char *)t - (char *)0) | ((char *)f - (char *)0) | l) & 7)) {
    const uint64_t *src = (const uint64_t *)f;
    const uint64_t *end = (const uint64_t *)((const char *)src + l);
    uint64_t *dst = (uint64_t *)t;
    while (src < end)
      *(dst++) = bswap_64(*(src++));
  } else {
    size_t i;
    char *dst = (char *)t;
    for (i = 0; i < l; i++)
      *(dst++) = ((char *)f)[i ^ 7];
  }
}

#ifdef HSK_BIG_ENDIAN
#define le2me_64(x) bswap_64(x)
#define me64_to_le_str(to, from, length) \
  swap_copy_u64_to_str((to), (from), (length))
#else
#define le2me_64(x) (x)
#define me64_to_le_str(to, from, length) \
  memcpy((to), (from), (length))
#endif

static uint64_t hsk_keccak_round_constants[HSK_SHA3_ROUNDS] = {
  I64(0x0000000000000001), I64(0x0000000000008082),
  I64(0x800000000000808A), I64(0x8000000080008000),
  I64(0x000000000000808B), I64(0x0000000080000001),
  I64(0x8000000080008081), I64(0x8000000000008009),
  I64(0x000000000000008A), I64(0x0000000000000088),
  I64(0x0000000080008009), I64(0x000000008000000A),
  I64(0x000000008000808B), I64(0x800000000000008B),
  I64(0x8000000000008089), I64(0x8000000000008003),
  I64(0x8000000000008002), I64(0x8000000000000080),
  I64(0x000000000000800A), I64(0x800000008000000A),
  I64(0x8000000080008081), I64(0x8000000000008080),
  I64(0x0000000080000001), I64(0x8000000080008008)
};

static void
hsk_keccak_init(hsk_sha3_ctx *ctx, unsigned bits) {
  unsigned rate = 1600 - bits * 2;

  memset(ctx, 0, sizeof(hsk_sha3_ctx));
  ctx->block_size = rate / 8;
  assert(rate <= 1600 && (rate % 64) == 0);
}

void
hsk_sha3_224_init(hsk_sha3_ctx *ctx) {
  hsk_keccak_init(ctx, 224);
}

void
hsk_sha3_256_init(hsk_sha3_ctx *ctx) {
  hsk_keccak_init(ctx, 256);
}

void
hsk_sha3_384_init(hsk_sha3_ctx *ctx) {
  hsk_keccak_init(ctx, 384);
}

void
hsk_sha3_512_init(hsk_sha3_ctx *ctx) {
  hsk_keccak_init(ctx, 512);
}

static void
hsk_keccak_theta(uint64_t *A) {
  unsigned int x;
  uint64_t C[5], D[5];

  for (x = 0; x < 5; x++)
    C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];

  D[0] = ROTL64(C[1], 1) ^ C[4];
  D[1] = ROTL64(C[2], 1) ^ C[0];
  D[2] = ROTL64(C[3], 1) ^ C[1];
  D[3] = ROTL64(C[4], 1) ^ C[2];
  D[4] = ROTL64(C[0], 1) ^ C[3];

  for (x = 0; x < 5; x++) {
    A[x] ^= D[x];
    A[x + 5] ^= D[x];
    A[x + 10] ^= D[x];
    A[x + 15] ^= D[x];
    A[x + 20] ^= D[x];
  }
}

static void
hsk_keccak_pi(uint64_t *A) {
  uint64_t A1;
  A1 = A[1];
  A[1] = A[6];
  A[6] = A[9];
  A[9] = A[22];
  A[22] = A[14];
  A[14] = A[20];
  A[20] = A[2];
  A[2] = A[12];
  A[12] = A[13];
  A[13] = A[19];
  A[19] = A[23];
  A[23] = A[15];
  A[15] = A[4];
  A[4] = A[24];
  A[24] = A[21];
  A[21] = A[8];
  A[8] = A[16];
  A[16] = A[5];
  A[5] = A[3];
  A[3] = A[18];
  A[18] = A[17];
  A[17] = A[11];
  A[11] = A[7];
  A[7] = A[10];
  A[10] = A1;
}

static void
hsk_keccak_chi(uint64_t *A) {
  int i;
  for (i = 0; i < 25; i += 5) {
    uint64_t A0 = A[0 + i], A1 = A[1 + i];
    A[0 + i] ^= ~A1 & A[2 + i];
    A[1 + i] ^= ~A[2 + i] & A[3 + i];
    A[2 + i] ^= ~A[3 + i] & A[4 + i];
    A[3 + i] ^= ~A[4 + i] & A0;
    A[4 + i] ^= ~A0 & A1;
  }
}

static void
hsk_sha3_permutation(uint64_t *state) {
  int round;
  for (round = 0; round < HSK_SHA3_ROUNDS; round++) {
    hsk_keccak_theta(state);

    state[1] = ROTL64(state[1], 1);
    state[2] = ROTL64(state[2], 62);
    state[3] = ROTL64(state[3], 28);
    state[4] = ROTL64(state[4], 27);
    state[5] = ROTL64(state[5], 36);
    state[6] = ROTL64(state[6], 44);
    state[7] = ROTL64(state[7], 6);
    state[8] = ROTL64(state[8], 55);
    state[9] = ROTL64(state[9], 20);
    state[10] = ROTL64(state[10], 3);
    state[11] = ROTL64(state[11], 10);
    state[12] = ROTL64(state[12], 43);
    state[13] = ROTL64(state[13], 25);
    state[14] = ROTL64(state[14], 39);
    state[15] = ROTL64(state[15], 41);
    state[16] = ROTL64(state[16], 45);
    state[17] = ROTL64(state[17], 15);
    state[18] = ROTL64(state[18], 21);
    state[19] = ROTL64(state[19], 8);
    state[20] = ROTL64(state[20], 18);
    state[21] = ROTL64(state[21], 2);
    state[22] = ROTL64(state[22], 61);
    state[23] = ROTL64(state[23], 56);
    state[24] = ROTL64(state[24], 14);

    hsk_keccak_pi(state);
    hsk_keccak_chi(state);

    *state ^= hsk_keccak_round_constants[round];
  }
}

static void
hsk_sha3_process_block(
  uint64_t hash[25],
  const uint64_t *block,
  size_t block_size
) {
  hash[0] ^= le2me_64(block[0]);
  hash[1] ^= le2me_64(block[1]);
  hash[2] ^= le2me_64(block[2]);
  hash[3] ^= le2me_64(block[3]);
  hash[4] ^= le2me_64(block[4]);
  hash[5] ^= le2me_64(block[5]);
  hash[6] ^= le2me_64(block[6]);
  hash[7] ^= le2me_64(block[7]);
  hash[8] ^= le2me_64(block[8]);

  if (block_size > 72) {
    hash[9] ^= le2me_64(block[9]);
    hash[10] ^= le2me_64(block[10]);
    hash[11] ^= le2me_64(block[11]);
    hash[12] ^= le2me_64(block[12]);

    if (block_size > 104) {
      hash[13] ^= le2me_64(block[13]);
      hash[14] ^= le2me_64(block[14]);
      hash[15] ^= le2me_64(block[15]);
      hash[16] ^= le2me_64(block[16]);

      if (block_size > 136) {
        hash[17] ^= le2me_64(block[17]);

        if (block_size > 144) {
          hash[18] ^= le2me_64(block[18]);
          hash[19] ^= le2me_64(block[19]);
          hash[20] ^= le2me_64(block[20]);
          hash[21] ^= le2me_64(block[21]);
          hash[22] ^= le2me_64(block[22]);
          hash[23] ^= le2me_64(block[23]);
          hash[24] ^= le2me_64(block[24]);
        }
      }
    }
  }

  hsk_sha3_permutation(hash);
}

void
hsk_sha3_update(hsk_sha3_ctx *ctx, const unsigned char *msg, size_t size) {
  size_t index = (size_t)ctx->rest;
  size_t block_size = (size_t)ctx->block_size;

  if (ctx->rest & HSK_SHA3_FINALIZED)
    return;

  ctx->rest = (unsigned)((ctx->rest + size) % block_size);

  if (index) {
    size_t left = block_size - index;
    memcpy((char *)ctx->message + index, msg, (size < left ? size : left));

    if (size < left)
      return;

    hsk_sha3_process_block(ctx->hash, ctx->message, block_size);
    msg += left;
    size -= left;
  }

  while (size >= block_size) {
    uint64_t *aligned_message_block;

    if (IS_ALIGNED_64(msg)) {
      aligned_message_block = (uint64_t *)msg;
    } else {
      memcpy(ctx->message, msg, block_size);
      aligned_message_block = ctx->message;
    }

    hsk_sha3_process_block(ctx->hash, aligned_message_block, block_size);
    msg += block_size;
    size -= block_size;
  }

  if (size)
    memcpy(ctx->message, msg, size);
}

void
hsk_sha3_final(hsk_sha3_ctx *ctx, unsigned char *result) {
  size_t digest_length = 100 - ctx->block_size / 2;
  const size_t block_size = ctx->block_size;

  if (!(ctx->rest & HSK_SHA3_FINALIZED)) {
    memset((char *)ctx->message + ctx->rest, 0, block_size - ctx->rest);
    ((char *)ctx->message)[ctx->rest] |= 0x06;
    ((char *)ctx->message)[block_size - 1] |= 0x80;

    hsk_sha3_process_block(ctx->hash, ctx->message, block_size);
    ctx->rest = HSK_SHA3_FINALIZED;
  }

  assert(block_size > digest_length);

  if (result)
    me64_to_le_str(result, ctx->hash, digest_length);
}

void
hsk_keccak_final(hsk_sha3_ctx *ctx, unsigned char *result) {
  size_t digest_length = 100 - ctx->block_size / 2;
  const size_t block_size = ctx->block_size;

  if (!(ctx->rest & HSK_SHA3_FINALIZED)) {
    memset((char *)ctx->message + ctx->rest, 0, block_size - ctx->rest);
    ((char *)ctx->message)[ctx->rest] |= 0x01;
    ((char *)ctx->message)[block_size - 1] |= 0x80;

    hsk_sha3_process_block(ctx->hash, ctx->message, block_size);
    ctx->rest = HSK_SHA3_FINALIZED;
  }

  assert(block_size > digest_length);

  if (result)
    me64_to_le_str(result, ctx->hash, digest_length);
}
