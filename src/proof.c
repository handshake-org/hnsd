#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "bio.h"
#include "blake2b.h"
#include "constants.h"
#include "error.h"
#include "hash.h"
#include "proof.h"

#define HSK_HAS_BIT(m, i) (((m)[(i) >> 3] >> (7 - ((i) & 7))) & 1)

static const uint8_t hsk_proof_internal[1] = {0x01};
static const uint8_t hsk_proof_leaf[1] = {0x00};

void
hsk_proof_init(hsk_proof_t *proof) {
  assert(proof);
  proof->type = 1;
  proof->nodes = NULL;
  proof->node_count = 0;
  proof->value = NULL;
  proof->value_size = 0;
  proof->nx_key = NULL;
  proof->nx_hash = NULL;
}

hsk_proof_t *
hsk_proof_alloc(void) {
  hsk_proof_t *proof = malloc(sizeof(hsk_proof_t));
  if (proof)
    hsk_proof_init(proof);
  return proof;
}

void
hsk_proof_uninit(hsk_proof_t *proof) {
  assert(proof);

  if (proof->nodes) {
    free(proof->nodes);
    proof->nodes = NULL;
    proof->node_count = 0;
  }

  if (proof->value) {
    free(proof->value);
    proof->value = NULL;
  }

  if (proof->nx_key) {
    free(proof->nx_key);
    proof->nx_key = NULL;
  }

  if (proof->nx_hash) {
    free(proof->nx_hash);
    proof->nx_hash = NULL;
  }
}

void
hsk_proof_free(hsk_proof_t *proof) {
  assert(proof);
  hsk_proof_uninit(proof);
  free(proof);
}

bool
hsk_proof_read(uint8_t **data, size_t *data_len, hsk_proof_t *proof) {
  assert(data && proof);
  assert(proof->node_count == 0);

  uint16_t field;

  if (!read_u16(data, data_len, &field))
    return false;

  proof->type = field >> 14;

  size_t count = field & ~(3 << 14);

  if (count > 256)
    return false;

  size_t bsize = (count + 7) / 8;
  uint8_t *map;

  if (!slice_bytes(data, data_len, &map, bsize))
    return false;

  proof->nodes = malloc(count * 32);

  if (!proof->nodes)
    return false;

  proof->node_count = count;

  memset(proof->nodes, 0x00, count * 32);

  size_t i;
  for (i = 0; i < count; i++) {
    if (HSK_HAS_BIT(map, i))
      continue;

    if (!read_bytes(data, data_len, &proof->nodes[i * 32], 32))
      goto fail;
  }

  switch (proof->type) {
    case HSK_PROOF_EXISTS:
      if (!read_u16(data, data_len, &proof->value_size))
        goto fail;

      if (proof->value_size > 512)
        goto fail;

      if (!alloc_bytes(data, data_len, &proof->value, proof->value_size))
        goto fail;
      break;
    case HSK_PROOF_DEADEND:
      break;
    case HSK_PROOF_COLLISION:
      if (!alloc_bytes(data, data_len, &proof->nx_key, 32))
        goto fail;

      if (!alloc_bytes(data, data_len, &proof->nx_hash, 32))
        goto fail;
      break;
    case HSK_PROOF_UNKNOWN:
      goto fail;
    default:
      assert(0 && "bad type");
      break;
  }

  return true;

fail:
  hsk_proof_uninit(proof);
  return false;
}

bool
hsk_proof_decode(const uint8_t *data, size_t data_len, hsk_proof_t *proof) {
  return hsk_proof_read((uint8_t **)&data, &data_len, proof);
}

static void
hsk_proof_hash_internal(
  const uint8_t *left,
  const uint8_t *right,
  uint8_t *out
) {
  hsk_blake2b_ctx ctx;
  assert(hsk_blake2b_init(&ctx, 32) == 0);
  hsk_blake2b_update(&ctx, hsk_proof_internal, 1);
  hsk_blake2b_update(&ctx, left, 32);
  hsk_blake2b_update(&ctx, right, 32);
  assert(hsk_blake2b_final(&ctx, out, 32) == 0);
}

static void
hsk_proof_hash_leaf(const uint8_t *key, const uint8_t *hash, uint8_t *out) {
  hsk_blake2b_ctx ctx;
  assert(hsk_blake2b_init(&ctx, 32) == 0);
  hsk_blake2b_update(&ctx, hsk_proof_leaf, 1);
  hsk_blake2b_update(&ctx, key, 32);
  hsk_blake2b_update(&ctx, hash, 32);
  assert(hsk_blake2b_final(&ctx, out, 32) == 0);
}

static void
hsk_proof_hash_value(
  const uint8_t *key,
  const uint8_t *value,
  size_t value_size,
  uint8_t *out
) {
  hsk_blake2b_ctx ctx;
  assert(hsk_blake2b_init(&ctx, 32) == 0);
  hsk_blake2b_update(&ctx, value, value_size);
  assert(hsk_blake2b_final(&ctx, out, 32) == 0);
  hsk_proof_hash_leaf(key, out, out);
}

int
hsk_proof_verify(
  const uint8_t *root,
  const uint8_t *key,
  const hsk_proof_t *proof,
  bool *exists,
  uint8_t **data,
  size_t *data_len
) {
  if (root == NULL || key == NULL || proof == NULL)
    return HSK_EBADARGS;

  uint8_t leaf[32];

  assert(proof->nodes || proof->node_count == 0);
  assert(proof->node_count <= 256);
  assert(proof->value_size <= 512);

  // Re-create the leaf.
  switch (proof->type) {
    case HSK_PROOF_EXISTS:
      assert(proof->value || proof->value_size == 0);
      assert(!proof->nx_key);
      assert(!proof->nx_hash);
      hsk_proof_hash_value(key, proof->value, proof->value_size, leaf);
      break;
    case HSK_PROOF_DEADEND:
      assert(!proof->value);
      assert(proof->value_size == 0);
      assert(!proof->nx_key);
      assert(!proof->nx_hash);
      memset(leaf, 0x00, 32);
      break;
    case HSK_PROOF_COLLISION:
      assert(!proof->value);
      assert(proof->value_size == 0);
      assert(proof->nx_key);
      assert(proof->nx_hash);
      if (memcmp(proof->nx_key, key, 32) == 0)
        return HSK_EHASHMISMATCH;
      hsk_proof_hash_leaf(proof->nx_key, proof->nx_hash, leaf);
      break;
    default:
      assert(0 && "unknown type");
      break;
  }

  uint8_t *next = &leaf[0];
  int depth = ((int)proof->node_count) - 1;

  // Traverse bits right to left.
  while (depth >= 0) {
    uint8_t *node = &proof->nodes[depth * 32];

    if (HSK_HAS_BIT(key, depth))
      hsk_proof_hash_internal(node, next, next);
    else
      hsk_proof_hash_internal(next, node, next);

    depth -= 1;
  }

  if (memcmp(next, root, 32) != 0)
    return HSK_EHASHMISMATCH;

  if (exists)
    *exists = proof->type == 0;

  if (data_len)
    *data_len = proof->value_size;

  if (data) {
    if (proof->value_size > 0) {
      *data = malloc(proof->value_size);
      if (!*data)
        return HSK_ENOMEM;
      memcpy(*data, proof->value, proof->value_size);
    } else {
      *data = NULL;
    }
  }

  return HSK_EPROOFOK;
}
