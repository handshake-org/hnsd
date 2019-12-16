#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "bio.h"
#include "blake2b.h"
#include "bn.h"
#include "constants.h"
#include "error.h"
#include "hash.h"
#include "header.h"
#include "sha3.h"
#include "utils.h"

void
hsk_header_init(hsk_header_t *hdr) {
  if (!hdr)
    return;

  // Preheader.
  hdr->nonce = 0;
  hdr->time = 0;
  memset(hdr->prev_block, 0, 32);
  memset(hdr->name_root, 0, 32);

  // Subheader.
  memset(hdr->extra_nonce, 0, 24);
  memset(hdr->reserved_root, 0, 32);
  memset(hdr->witness_root, 0, 32);
  memset(hdr->merkle_root, 0, 32);
  hdr->version = 0;
  hdr->bits = 0;

  // Mask.
  memset(hdr->mask, 0, 32);

  hdr->cache = false;
  memset(hdr->hash, 0, 32);
  hdr->height = 0;
  memset(hdr->work, 0, 32);

  hdr->next = NULL;
}

hsk_header_t *
hsk_header_alloc(void) {
  hsk_header_t *hdr = malloc(sizeof(hsk_header_t));
  hsk_header_init(hdr);
  return hdr;
}

hsk_header_t *
hsk_header_clone(const hsk_header_t *hdr) {
  if (!hdr)
    return NULL;

  hsk_header_t *copy = malloc(sizeof(hsk_header_t));

  if (!copy)
    return NULL;

  memcpy((void *)copy, (void *)hdr, sizeof(hsk_header_t));
  copy->next = NULL;

  return copy;
}

bool
hsk_pow_to_target(uint32_t bits, uint8_t *target) {
  assert(target);

  memset(target, 0, 32);

  if (bits == 0)
    return false;

  // No negatives.
  if ((bits >> 23) & 1)
    return false;

  uint32_t exponent = bits >> 24;
  uint32_t mantissa = bits & 0x7fffff;

  uint32_t shift;

  if (exponent <= 3) {
    mantissa >>= 8 * (3 - exponent);
    shift = 0;
  } else {
    shift = (exponent - 3) & 31;
  }

  int i = 31 - shift;

  while (mantissa && i >= 0) {
    target[i--] = (uint8_t)mantissa;
    mantissa >>= 8;
  }

  // Overflow
  if (mantissa)
    return false;

  return true;
}

bool
hsk_pow_to_bits(const uint8_t *target, uint32_t *bits) {
  assert(target && bits);

  int i;

  for (i = 0; i < 32; i++) {
    if (target[i] != 0)
      break;
  }

  uint32_t exponent = 32 - i;

  if (exponent == 0) {
    *bits = 0;
    return true;
  }

  uint32_t mantissa = 0;

  if (exponent <= 3) {
    switch (exponent) {
      case 3:
        mantissa |= ((uint32_t)target[29]) << 16;
      case 2:
        mantissa |= ((uint32_t)target[30]) << 8;
      case 1:
        mantissa |= (uint32_t)target[31];
    }
    mantissa <<= 8 * (3 - exponent);
  } else {
    int shift = exponent - 3;
    for (; i < 32 - shift; i++) {
      mantissa <<= 8;
      mantissa |= target[i];
    }
  }

  if (mantissa & 0x800000) {
    mantissa >>= 8;
    exponent += 1;
  }

  *bits = (exponent << 24) | mantissa;

  return true;
}

bool
hsk_header_get_proof(const hsk_header_t *hdr, uint8_t *proof) {
  uint8_t target[32];

  if (!hsk_pow_to_target(hdr->bits, target))
    return false;

  hsk_bn_t max_bn;
  hsk_bn_from_int(&max_bn, 1);
  hsk_bn_lshift(&max_bn, &max_bn, 256);

  hsk_bn_t target_bn;
  hsk_bn_from_array(&target_bn, target, 32);
  hsk_bn_inc(&target_bn);

  // (1 << 256) / (target + 1)
  hsk_bn_div(&max_bn, &target_bn, &target_bn);

  hsk_bn_to_array(&target_bn, proof, 32);

  return true;
}

bool
hsk_header_calc_work(hsk_header_t *hdr, const hsk_header_t *prev) {
  if (!prev)
    return hsk_header_get_proof(hdr, hdr->work);

  hsk_bn_t prev_bn;
  hsk_bn_from_array(&prev_bn, prev->work, 32);

  uint8_t proof[32];

  if (!hsk_header_get_proof(hdr, proof))
    return false;

  hsk_bn_t proof_bn;
  hsk_bn_from_array(&proof_bn, proof, 32);

  hsk_bn_add(&prev_bn, &proof_bn, &proof_bn);
  hsk_bn_to_array(&proof_bn, hdr->work, 32);

  return true;
}

bool
hsk_header_read(uint8_t **data, size_t *data_len, hsk_header_t *hdr) {
  if (!read_u32(data, data_len, &hdr->nonce))
    return false;

  if (!read_u64(data, data_len, &hdr->time))
    return false;

  if (!read_bytes(data, data_len, hdr->prev_block, 32))
    return false;

  if (!read_bytes(data, data_len, hdr->name_root, 32))
    return false;

  if (!read_bytes(data, data_len, hdr->extra_nonce, 24))
    return false;

  if (!read_bytes(data, data_len, hdr->reserved_root, 32))
    return false;

  if (!read_bytes(data, data_len, hdr->witness_root, 32))
    return false;

  if (!read_bytes(data, data_len, hdr->merkle_root, 32))
    return false;

  if (!read_u32(data, data_len, &hdr->version))
    return false;

  if (!read_u32(data, data_len, &hdr->bits))
    return false;

  if (!read_bytes(data, data_len, hdr->mask, 32))
    return false;

  return true;
}

bool
hsk_header_decode(const uint8_t *data, size_t data_len, hsk_header_t *hdr) {
  return hsk_header_read((uint8_t **)&data, &data_len, hdr);
}

int
hsk_header_write(const hsk_header_t *hdr, uint8_t **data) {
  int s = 0;
  s += write_u32(data, hdr->nonce);
  s += write_u64(data, hdr->time);
  s += write_bytes(data, hdr->prev_block, 32);
  s += write_bytes(data, hdr->name_root, 32);
  s += write_bytes(data, hdr->extra_nonce, 24);
  s += write_bytes(data, hdr->reserved_root, 32);
  s += write_bytes(data, hdr->witness_root, 32);
  s += write_bytes(data, hdr->merkle_root, 32);
  s += write_u32(data, hdr->version);
  s += write_u32(data, hdr->bits);
  s += write_bytes(data, hdr->mask, 32);
  return s;
}

int
hsk_header_size(const hsk_header_t *hdr) {
  return hsk_header_write(hdr, NULL);
}

int
hsk_header_encode(const hsk_header_t *hdr, uint8_t *data) {
  return hsk_header_write(hdr, &data);
}

int
hsk_header_pre_write(const hsk_header_t *hdr, uint8_t **data) {
  int s = 0;
  uint8_t pad[20];
  uint8_t commit_hash[32];

  hsk_header_padding(hdr, pad, 20);
  hsk_header_commit_hash(hdr, commit_hash);

  s += write_u32(data, hdr->nonce);
  s += write_u64(data, hdr->time);
  s += write_bytes(data, pad, 20);
  s += write_bytes(data, hdr->prev_block, 32);
  s += write_bytes(data, hdr->name_root, 32);
  s += write_bytes(data, commit_hash, 32);
  return s;
}

int
hsk_header_pre_size(const hsk_header_t *hdr) {
  return hsk_header_pre_write(hdr, NULL);
}

int
hsk_header_pre_encode(const hsk_header_t *hdr, uint8_t *data) {
  return hsk_header_pre_write(hdr, &data);
}

int
hsk_header_sub_write(const hsk_header_t *hdr, uint8_t **data) {
  int s = 0;
  s += write_bytes(data, hdr->extra_nonce, 24);
  s += write_bytes(data, hdr->reserved_root, 32);
  s += write_bytes(data, hdr->witness_root, 32);
  s += write_bytes(data, hdr->merkle_root, 32);
  s += write_u32(data, hdr->version);
  s += write_u32(data, hdr->bits);
  return s;
}

int
hsk_header_sub_size(const hsk_header_t *hdr) {
  return hsk_header_sub_write(hdr, NULL);
}

int
hsk_header_sub_encode(const hsk_header_t *hdr, uint8_t *data) {
  return hsk_header_sub_write(hdr, &data);
}

void
hsk_header_sub_hash(const hsk_header_t *hdr, uint8_t *hash) {
  int size = hsk_header_sub_size(hdr);
  uint8_t sub[size];
  hsk_header_sub_encode(hdr, sub);
  hsk_hash_blake256(sub, size, hash);
}

void
hsk_header_mask_hash(const hsk_header_t *hdr, uint8_t *hash) {
  hsk_blake2b_ctx ctx;
  assert(hsk_blake2b_init(&ctx, 32) == 0);
  hsk_blake2b_update(&ctx, hdr->prev_block, 32);
  hsk_blake2b_update(&ctx, hdr->mask, 32);
  assert(hsk_blake2b_final(&ctx, hash, 32) == 0);
}

void
hsk_header_commit_hash(const hsk_header_t *hdr, uint8_t *hash) {
  uint8_t sub_hash[32];
  uint8_t mask_hash[32];

  hsk_header_sub_hash(hdr, sub_hash);
  hsk_header_mask_hash(hdr, mask_hash);

  hsk_blake2b_ctx ctx;
  assert(hsk_blake2b_init(&ctx, 32) == 0);
  hsk_blake2b_update(&ctx, sub_hash, 32);
  hsk_blake2b_update(&ctx, mask_hash, 32);
  assert(hsk_blake2b_final(&ctx, hash, 32) == 0);
}

void
hsk_header_padding(const hsk_header_t *hdr, uint8_t *pad, size_t size) {
  assert(hdr && pad);

  size_t i;

  for (i = 0; i < size; i++)
    pad[i] = hdr->prev_block[i % 32] ^ hdr->name_root[i % 32];
}

bool
hsk_header_equal(hsk_header_t *a, hsk_header_t *b) {
  return memcmp(hsk_header_cache(a), hsk_header_cache(b), 32) == 0;
}

const uint8_t *
hsk_header_cache(hsk_header_t *hdr) {
  if (hdr->cache)
    return hdr->hash;

  int size = hsk_header_pre_size(hdr);
  uint8_t pre[size];
  uint8_t pad8[8];
  uint8_t pad32[32];
  uint8_t left[64];
  uint8_t right[32];

  // Generate pads.
  hsk_header_padding(hdr, pad8, 8);
  hsk_header_padding(hdr, pad32, 32);

  // Generate left.
  hsk_header_pre_encode(hdr, pre);
  hsk_hash_blake512(pre, size, left);

  // Generate right.
  hsk_sha3_ctx s_ctx;
  hsk_sha3_256_init(&s_ctx);
  hsk_sha3_update(&s_ctx, pre, size);
  hsk_sha3_update(&s_ctx, pad8, 8);
  hsk_sha3_final(&s_ctx, right);

  // Generate hash.
  hsk_blake2b_ctx b_ctx;
  assert(hsk_blake2b_init(&b_ctx, 32) == 0);
  hsk_blake2b_update(&b_ctx, left, 64);
  hsk_blake2b_update(&b_ctx, pad32, 32);
  hsk_blake2b_update(&b_ctx, right, 32);
  assert(hsk_blake2b_final(&b_ctx, hdr->hash, 32) == 0);

  // XOR PoW hash with arbitrary bytes.
  // This can be used by mining pools to
  // mitigate block witholding attacks.
  int i;
  for (i = 0; i < 32; i++)
    hdr->hash[i] ^= hdr->mask[i];

  hdr->cache = true;

  return hdr->hash;
}

void
hsk_header_hash(hsk_header_t *hdr, uint8_t *hash) {
  memcpy(hash, hsk_header_cache(hdr), 32);
}

int
hsk_header_verify_pow(const hsk_header_t *hdr) {
  uint8_t target[32];

  if (!hsk_pow_to_target(hdr->bits, target))
    return HSK_ENEGTARGET;

  uint8_t hash[32];

  hsk_header_hash((hsk_header_t *)hdr, hash);

  if (memcmp(hash, target, 32) > 0)
    return HSK_EHIGHHASH;

  return HSK_SUCCESS;
}

void
hsk_header_print(hsk_header_t *hdr, const char *prefix) {
  assert(hdr);

  char hash[65];
  char work[65];
  char prev_block[65];
  char name_root[65];
  char extra_nonce[49];
  char reserved_root[65];
  char witness_root[65];
  char merkle_root[65];
  char mask[65];

  assert(hsk_hex_encode(hsk_header_cache(hdr), 32, hash));
  assert(hsk_hex_encode(hdr->work, 32, work));
  assert(hsk_hex_encode(hdr->prev_block, 32, prev_block));
  assert(hsk_hex_encode(hdr->name_root, 32, name_root));
  assert(hsk_hex_encode(hdr->extra_nonce, 24, extra_nonce));
  assert(hsk_hex_encode(hdr->reserved_root, 32, reserved_root));
  assert(hsk_hex_encode(hdr->witness_root, 32, witness_root));
  assert(hsk_hex_encode(hdr->merkle_root, 32, merkle_root));
  assert(hsk_hex_encode(hdr->mask, 32, mask));

  printf("%sheader\n", prefix);
  printf("%s  hash=%s\n", prefix, hash);
  printf("%s  height=%u\n", prefix, hdr->height);
  printf("%s  work=%s\n", prefix, work);
  printf("%s  nonce=%u\n", prefix, hdr->nonce);
  printf("%s  time=%u\n", prefix, (uint32_t)hdr->time);
  printf("%s  prev_block=%s\n", prefix, prev_block);
  printf("%s  name_root=%s\n", prefix, name_root);
  printf("%s  extra_nonce=%s\n", prefix, extra_nonce);
  printf("%s  reserved_root=%s\n", prefix, reserved_root);
  printf("%s  witness_root=%s\n", prefix, witness_root);
  printf("%s  merkle_root=%s\n", prefix, merkle_root);
  printf("%s  version=%u\n", prefix, hdr->version);
  printf("%s  bits=%u\n", prefix, hdr->bits);
  printf("%s  mask=%s\n", prefix, mask);
}
