#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "hsk-cuckoo.h"
#include "hsk-error.h"
#include "blake2b.h"
#include "siphash.h"

int32_t
hsk_cuckoo_init(
  hsk_cuckoo_t *ctx,
  int32_t bits,
  int32_t size,
  int32_t ease,
  bool legacy
) {
  if (ctx == NULL)
    return HSK_EBADARGS;

  if (bits < 1 || bits > 32)
    return HSK_EBADARGS;

  if (size < 4 || size > 254)
    return HSK_EBADARGS;

  if (size & 1)
    return HSK_EBADARGS;

  if (ease < 1 || ease > 100)
    return HSK_EBADARGS;

  // Maximum number of nodes on the graph (NNODES).
  ctx->nodes = 1ull << bits;

  // Mask of edges for convenience (EDGEMASK).
  ctx->mask = (ctx->nodes >> 1) - 1;

  // Size of cycle to find (PROOFSIZE).
  // The odds of a graph containing an
  // L-cycle are 1 in L.
  ctx->size = size;

  // Maximum nonce size (easipct->easiness).
  ctx->easiness = ((uint64_t)ease * ctx->nodes) / 100;

  // Sanity check.
  assert(ease != 50 || ctx->easiness == (ctx->mask + 1));

  // Which style of hashing to use (SIPHASH_COMPAT).
  ctx->legacy = legacy;

  return HSK_SUCCESS;
}

int32_t
hsk_cuckoo_sipkey(
  hsk_cuckoo_t *ctx,
  uint8_t *hdr,
  size_t hdr_len,
  uint8_t *key
) {
  if (ctx == NULL || hdr == NULL)
    return HSK_EBADARGS;

  hsk_blake2b_ctx blake;

  assert(hsk_blake2b_init(&blake, 32) == 0);
  hsk_blake2b_update(&blake, hdr, hdr_len);
  hsk_blake2b_final(&blake, key, 32);

  return HSK_SUCCESS;
}

uint32_t
hsk_cuckoo_sipnode(
  hsk_cuckoo_t *ctx,
  uint8_t *key,
  uint32_t nonce,
  int32_t uorv
) {
  assert(ctx != NULL);
  assert(key != NULL);
  assert(uorv == 0 || uorv == 1);

  uint32_t num = (nonce << 1) | uorv;
  uint32_t node;

  if (ctx->legacy)
    node = hsk_siphash32(num, key) & ctx->mask;
  else
    node = hsk_siphash32k256(num, key) & ctx->mask;

  return (node << 1) | uorv;
}

int32_t
hsk_cuckoo_verify(hsk_cuckoo_t *ctx, uint8_t *key, uint32_t *nonces) {
  if (ctx == NULL || key == NULL || nonces == NULL)
    return HSK_EBADARGS;

  uint32_t uvs[ctx->size * 2];

  uint32_t xor0 = 0;
  uint32_t xor1 = 0;

  for (int32_t n = 0; n < ctx->size; n++) {
    if (nonces[n] >= ctx->easiness)
      return HSK_EPOWTOOBIG;

    if (n > 0 && nonces[n] <= nonces[n - 1])
      return HSK_EPOWTOOSMALL;

    uint32_t x = hsk_cuckoo_sipnode(ctx, key, nonces[n], 0);
    uint32_t y = hsk_cuckoo_sipnode(ctx, key, nonces[n], 1);

    uvs[2 * n] = x;
    uvs[2 * n + 1] = y;

    xor0 ^= x;
    xor1 ^= y;
  }

  if (xor0 | xor1)
    return HSK_EPOWNONMATCHING;

  uint32_t n = 0;
  uint32_t i = 0;

  do {
    uint32_t j = i;
    uint32_t k = j;

    for (;;) {
      k = (k + 2) % (2 * ctx->size);

      if (k == i)
        break;

      if (uvs[k] == uvs[i]) {
        if (j != i)
          return HSK_EPOWBRANCH;

        j = k;
      }
    }

    if (j == i)
      return HSK_EPOWDEADEND;

    i = j ^ 1;
    n += 1;
  } while (i != 0);

  if (n != ctx->size)
    return HSK_EPOWSHORTCYCLE;

  return HSK_EPOWOK;
}

int32_t
hsk_cuckoo_verify_header(
  hsk_cuckoo_t *ctx,
  uint8_t *hdr,
  size_t hdr_len,
  uint32_t *sol,
  size_t sol_size
) {
  if (ctx == NULL || hdr == NULL || sol == NULL)
    return HSK_EBADARGS;

  if (sol_size != ctx->size)
    return HSK_EPOWPROOFSIZE;

  uint8_t key[32];

  if (hsk_cuckoo_sipkey(ctx, hdr, hdr_len, key) != 0)
    return HSK_EBADARGS;

  return hsk_cuckoo_verify(ctx, key, sol);
}
