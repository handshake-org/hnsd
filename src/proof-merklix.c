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

static const uint8_t hsk_proof_skip[1] = {0x02};
static const uint8_t hsk_proof_internal[1] = {0x01};
static const uint8_t hsk_proof_leaf[1] = {0x00};

static inline bool
read_bitlen(uint8_t **data, size_t *len, uint16_t *bits, size_t *bytes) {
  uint8_t byte;

  if (!read_u8(data, data_len, &byte))
    return false;

  uint16_t size = byte;

  if (size & 0x80) {
    size &= ~0x80;
    size <<= 8;

    if (!read_u8(data, data_len, &byte))
      return false;

    size |= byte;
  }

  if (size == 0 || size > 256)
    return false;

  *bits = (uint16_t)size;
  *bytes = ((size_t)size + 7) / 8;

  return true;
}

void
hsk_proof_init(hsk_proof_t *proof) {
  assert(proof);
  proof->type = HSK_PROOF_DEADEND;
  proof->depth = 0;
  proof->nodes = NULL;
  proof->node_count = 0;
  proof->prefix = NULL;
  proof->prefix_size = 0;
  proof->left = NULL;
  proof->right = NULL;
  proof->nx_key = NULL;
  proof->nx_hash = NULL;
  proof->value = NULL;
  proof->value_size = 0;
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

  if (proof->prefix) {
    free(proof->prefix);
    proof->prefix = NULL;
    proof->prefix_size = 0;
  }

  if (proof->left) {
    free(proof->left);
    proof->left = NULL;
  }

  if (proof->right) {
    free(proof->right);
    proof->right = NULL;
  }

  if (proof->nx_key) {
    free(proof->nx_key);
    proof->nx_key = NULL;
  }

  if (proof->nx_hash) {
    free(proof->nx_hash);
    proof->nx_hash = NULL;
  }

  if (proof->value) {
    free(proof->value);
    proof->value = NULL;
    proof->value_size = 0;
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
  proof->depth = field & ~(3 << 14);

  if (proof->depth > 256)
    return false;

  uint16_t count;

  if (!read_u16(data, data_len, &count))
    return false;

  if (count > 256)
    return false;

  size_t bsize = (count + 7) / 8;
  uint8_t *map;

  if (!slice_bytes(data, data_len, &map, bsize))
    return false;

  proof->nodes = calloc(count, sizeof(hsk_proof_node_t));

  if (count > 0 && !proof->nodes)
    return false;

  proof->node_count = count;

  size_t i;
  for (i = 0; i < count; i++) {
    hsk_proof_node_t *item = &proof->nodes[i];

    if (HSK_HAS_BIT(map, i)) {
      uint16_t size;
      size_t bytes;

      if (!read_bitlen(data, data_len, &size, &bytes))
        goto fail;

      if (!read_bytes(data, data_len, &item->prefix[0], bytes))
        goto fail;

      item->prefix_size = size;
    }

    if (!read_bytes(data, data_len, &item->node[0], 32))
      goto fail;
  }

  switch (proof->type) {
    case HSK_PROOF_DEADEND: {
      break;
    }

    case HSK_PROOF_SHORT: {
      uint16_t size;
      size_t bytes;

      if (!read_bitlen(data, data_len, &size, &bytes))
        goto fail;

      if (!alloc_bytes(data, data_len, &proof->prefix, bytes))
        goto fail;

      proof->prefix_size = size;

      if (!alloc_bytes(data, data_len, &proof->left, 32))
        goto fail;

      if (!alloc_bytes(data, data_len, &proof->right, 32))
        goto fail;

      break;
    }

    case HSK_PROOF_COLLISION: {
      if (!alloc_bytes(data, data_len, &proof->nx_key, 32))
        goto fail;

      if (!alloc_bytes(data, data_len, &proof->nx_hash, 32))
        goto fail;

      break;
    }

    case HSK_PROOF_EXISTS: {
      if (!read_u16(data, data_len, &proof->value_size))
        goto fail;

      if (proof->value_size > 512 + 13)
        goto fail;

      if (!alloc_bytes(data, data_len, &proof->value, proof->value_size))
        goto fail;

      break;
    }

    default: {
      assert(0 && "bad type");
      break;
    }
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
  const uint8_t *prefix,
  uint16_t prefix_size,
  const uint8_t *left,
  const uint8_t *right,
  uint8_t *out
) {
  hsk_blake2b_ctx ctx;
  assert(hsk_blake2b_init(&ctx, 32) == 0);

  if (prefix_size == 0) {
    hsk_blake2b_update(&ctx, hsk_proof_internal, 1);
    hsk_blake2b_update(&ctx, left, 32);
    hsk_blake2b_update(&ctx, right, 32);
  } else {
    uint8_t size[2];
    uint8_t *p = &size[0];
    write_u16(p, prefix_size);

    size_t bytes = ((size_t)prefix_size + 7) / 8;

    hsk_blake2b_update(&ctx, hsk_proof_skip, 1);
    hsk_blake2b_update(&ctx, size, 2);
    hsk_blake2b_update(&ctx, prefix, bytes);
    hsk_blake2b_update(&ctx, left, 32);
    hsk_blake2b_update(&ctx, right, 32);
  }

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

static bool
hsk_proof_has(
  const uint8_t *prefix,
  uint16_t prefix_size,
  const uint8_t *key,
  uint16_t depth
) {
  int xs = prefix_size;
  int ys = 256 - depth;
  int len = xs < ys ? xs : ys;

  assert(len >= 0 && len <= 256);

  int x = 0;
  int y = depth;
  int c = 0;
  int i;

  for (i = 0; i < len; i++) {
    if (HSK_HAS_BIT(prefix, x) != HSK_HAS_BIT(key, y))
      break;

    x += 1;
    y += 1;
    c += 1;
  }

  return c == prefix_size;
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

  assert(proof->depth <= 256);
  assert(proof->nodes || proof->node_count == 0);
  assert(proof->node_count <= 256);
  assert(proof->value_size <= 512 + 13);

  // Re-create the leaf.
  switch (proof->type) {
    case HSK_PROOF_DEADEND: {
      memset(leaf, 0x00, 32);
      break;
    }

    case HSK_PROOF_SHORT: {
      uint8_t *prefix = proof->prefix;
      uint16_t prefix_size = proof->prefix_size;
      uint8_t *left = proof->left;
      uint8_t *right = proof->right;

      assert(proof->prefix);
      assert(proof->prefix_size != 0);
      assert(proof->left);
      assert(proof->right);

      if (!hsk_proof_has(prefix, prefix_size, key, proof->depth))
        return HSK_ESAMEPATH;

      hsk_proof_hash_internal(prefix, prefix_size, left, right, leaf);

      break;
    }

    case HSK_PROOF_COLLISION: {
      assert(proof->nx_key);
      assert(proof->nx_hash);

      if (memcmp(proof->nx_key, key, 32) == 0)
        return HSK_ESAMEKEY;

      hsk_proof_hash_leaf(proof->nx_key, proof->nx_hash, leaf);
      break;
    }

    case HSK_PROOF_EXISTS: {
      assert(proof->value || proof->value_size == 0);
      hsk_proof_hash_value(key, proof->value, proof->value_size, leaf);
      break;
    }

    default:
      assert(0 && "unknown type");
      break;
  }

  uint8_t *next = &leaf[0];
  int depth = (int)proof->depth;
  int i = ((int)proof->node_count) - 1;

  // Traverse bits right to left.
  for (; i >= 0; i--) {
    hsk_proof_node_t *item = &proof->nodes[i];
    uint8_t *prefix = &item->prefix[0];
    uint16_t prefix_size = item->prefix_size;
    uint8_t *node = &item->node[0];

    if (depth < prefix_size + 1)
      return HSK_ENEGDEPTH;

    depth -= 1;

    if (HSK_HAS_BIT(key, depth))
      hsk_proof_hash_internal(prefix, prefix_size, node, next, next);
    else
      hsk_proof_hash_internal(prefix, prefix_size, next, node, next);

    depth -= prefix_size;

    if (!hsk_proof_has(prefix, prefix_size, key, depth))
      return HSK_EPATHMISMATCH;
  }

  if (depth != 0)
    return HSK_ETOODEEP;

  if (memcmp(next, root, 32) != 0)
    return HSK_EHASHMISMATCH;

  if (exists)
    *exists = proof->type == HSK_PROOF_EXISTS;

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
