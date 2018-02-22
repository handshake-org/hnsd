#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include "hsk-error.h"
#include "bio.h"
#include "hsk-hash.h"
#include "hsk-header.h"
#include "hsk-cuckoo.h"
#include "bn.h"
#include "utils.h"

bool
hsk_to_target(uint32_t bits, uint8_t *target) {
  assert(target != NULL);

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

  int32_t i = 31 - shift;

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
hsk_to_bits(uint8_t *target, uint32_t *bits) {
  assert(target != NULL);
  assert(bits != NULL);

  int32_t i;

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
    int32_t shift = exponent - 3;
    for (; i < 31 - shift; i++) {
      mantissa <<= 8;
      mantissa |= target[i];
    }
  }

  // No negatives.
  if (mantissa & 0x800000)
    return false;

  *bits = (exponent << 24) | mantissa;

  return true;
}

bool
hsk_get_proof2(uint32_t bits, uint8_t *proof) {
  uint8_t target[32];

  if (!hsk_to_target(bits, target))
    return false;

  bn_t max_bn;
  bignum_from_int(&max_bn, 1);
  bignum_lshift(&max_bn, &max_bn, 256);

  bn_t target_bn;
  bignum_from_array(&target_bn, target, 32);
  bignum_inc(&target_bn);

  // (1 << 256) / (target + 1)
  bignum_div(&max_bn, &target_bn, &target_bn);

  bignum_to_array(&target_bn, proof, 32);

  return true;
}

bool
hsk_get_work(uint8_t *prev, uint32_t bits, uint8_t *work) {
  bn_t prev_bn;
  bignum_from_array(&prev_bn, prev, 32);

  uint8_t proof[32];

  if (!hsk_get_proof2(bits, proof))
    return false;

  bn_t proof_bn;
  bignum_from_array(&proof_bn, proof, 32);

  bignum_add(&prev_bn, &proof_bn, &proof_bn);
  bignum_to_array(&proof_bn, work, 32);

  return true;
}

static bool
read_sol(uint8_t **data, size_t *data_len, uint32_t *sol, uint8_t sol_size) {
#ifdef HSK_LITTLE_ENDIAN
  int32_t size = (int32_t)sol_size << 2;
  if (!read_bytes(data, data_len, (uint8_t *)sol, size))
    return false;
#else
  int32_t i;
  for (i = 0; i < sol_size; i++) {
    if (!read_u32(data, data_len, sol + i))
      return false;
  }
#endif
  return true;
}

static size_t
write_sol(uint8_t **data, uint32_t *sol, uint8_t sol_size) {
#ifdef HSK_LITTLE_ENDIAN
  int32_t size = (int32_t)sol_size << 2;
  return write_bytes(data, (uint8_t *)sol, size);
#else
  int32_t i;
  for (i = 0; i < sol_size; i++)
    write_u32(data, sol[i]);
  return (int32_t)sol_size << 2;
#endif
}

static bool
encode_sol(uint8_t *data, uint32_t *sol, uint8_t sol_size) {
  return write_sol(&data, sol, sol_size);
}

bool
hsk_read_header(uint8_t **data, size_t *data_len, hsk_header_t *hdr) {
  if (!read_u32(data, data_len, &hdr->version))
    return false;

  if (!read_bytes(data, data_len, hdr->prev_block, 32))
    return false;

  if (!read_bytes(data, data_len, hdr->merkle_root, 32))
    return false;

  if (!read_bytes(data, data_len, hdr->witness_root, 32))
    return false;

  if (!read_bytes(data, data_len, hdr->trie_root, 32))
    return false;

  if (!read_u64(data, data_len, &hdr->time))
    return false;

  if (!read_u32(data, data_len, &hdr->bits))
    return false;

  if (!read_bytes(data, data_len, hdr->nonce, 16))
    return false;

  if (!read_u8(data, data_len, &hdr->sol_size))
    return false;

  if (hdr->sol_size > 42)
    return false;

  if (!read_sol(data, data_len, hdr->sol, hdr->sol_size))
    return false;

  return true;
}

bool
hsk_decode_header(uint8_t *data, size_t data_len, hsk_header_t *hdr) {
  return hsk_read_header(&data, &data_len, hdr);
}

int32_t
hsk_write_header(hsk_header_t *hdr, uint8_t **data) {
  int32_t s = 0;
  s += write_u32(data, hdr->version);
  s += write_bytes(data, hdr->prev_block, 32);
  s += write_bytes(data, hdr->merkle_root, 32);
  s += write_bytes(data, hdr->witness_root, 32);
  s += write_bytes(data, hdr->trie_root, 32);
  s += write_u64(data, hdr->time);
  s += write_u32(data, hdr->bits);
  s += write_bytes(data, hdr->nonce, 16);
  s += write_u8(data, hdr->sol_size);
  s += write_sol(data, hdr->sol, hdr->sol_size);
  return s;
}

int32_t
hsk_size_header(hsk_header_t *hdr) {
  return hsk_write_header(hdr, NULL);
}

int32_t
hsk_encode_header(hsk_header_t *hdr, uint8_t *data) {
  return hsk_write_header(hdr, &data);
}

int32_t
hsk_write_pre(hsk_header_t *hdr, uint8_t **data) {
  int32_t s = 0;
  s += write_u32(data, hdr->version);
  s += write_bytes(data, hdr->prev_block, 32);
  s += write_bytes(data, hdr->merkle_root, 32);
  s += write_bytes(data, hdr->witness_root, 32);
  s += write_bytes(data, hdr->trie_root, 32);
  s += write_u64(data, hdr->time);
  s += write_u32(data, hdr->bits);
  s += write_bytes(data, hdr->nonce, 16);
  return s;
}

int32_t
hsk_size_pre(hsk_header_t *hdr) {
  return hsk_write_pre(hdr, NULL);
}

int32_t
hsk_encode_pre(hsk_header_t *hdr, uint8_t *data) {
  return hsk_write_pre(hdr, &data);
}

bool
hsk_header_equal(hsk_header_t *a, hsk_header_t *b) {
  return memcmp(hsk_cache_header(a), hsk_cache_header(b), 32) == 0;
}

uint8_t *
hsk_cache_header(hsk_header_t *hdr) {
  if (hdr->cache)
    return hdr->hash;

  int32_t size = hsk_size_header(hdr);
  uint8_t raw[size];

  hsk_encode_header(hdr, raw);
  hsk_blake2b(raw, size, hdr->hash);
  hdr->cache = true;

  return hdr->hash;
}

void
hsk_hash_header(hsk_header_t *hdr, uint8_t *hash) {
  memcpy(hash, hsk_cache_header(hdr), 32);
}

void
hsk_hash_pre(hsk_header_t *hdr, uint8_t *hash) {
  int32_t size = hsk_size_pre(hdr);
  uint8_t raw[size];

  hsk_encode_pre(hdr, raw);
  hsk_blake2b(raw, size, hash);
}

int32_t
hsk_hash_sol(hsk_header_t *hdr, uint8_t *hash) {
  int32_t size = (int32_t)hdr->sol_size << 2;
  uint8_t raw[size];
  encode_sol(raw, hdr->sol, hdr->sol_size);
  hsk_blake2b(raw, size, hash);
}

static int32_t
rcmp(uint8_t *a, uint8_t *b, size_t size) {
  int32_t i = size - 1;
  int32_t j = 0;

  for (; i >= 0; i--, j++) {
    if (a[i] < b[j])
      return -1;

    if (a[i] > b[j])
      return 1;
  }

  return 0;
}

int32_t
hsk_verify_pow(hsk_header_t *hdr) {
  uint8_t target[32];

  if (!hsk_to_target(hdr->bits, target))
    return HSK_NEGTARGET;

  int32_t size = (int32_t)hdr->sol_size << 2;

  uint8_t raw[size];
  encode_sol(raw, hdr->sol, hdr->sol_size);

  uint8_t hash[32];
  hsk_blake2b(raw, size, hash);

  if (rcmp(hash, target, 32) > 0)
    return HSK_HIGHHASH;

  hsk_cuckoo_t ctx;
  // testnet:
  assert(hsk_cuckoo_init(&ctx, 16, 18, 50, false) == 0);
  // main:
  // assert(hsk_cuckoo_init(&ctx, 30, 42, 50, false) == 0);

  size_t psize = hsk_size_pre(hdr);
  uint8_t pre[psize];
  hsk_encode_pre(hdr, pre);

  return hsk_cuckoo_verify_header(&ctx, pre, psize, hdr->sol, hdr->sol_size);
}
