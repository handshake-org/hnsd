#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "bio.h"
#include "bn.h"
#include "constants.h"
#include "cuckoo.h"
#include "error.h"
#include "hash.h"
#include "header.h"
#include "utils.h"

void
hsk_header_init(hsk_header_t *hdr) {
  if (!hdr)
    return;

  hdr->version = 0;
  memset(hdr->prev_block, 0, 32);
  memset(hdr->merkle_root, 0, 32);
  memset(hdr->name_root, 0, 32);
  memset(hdr->reserved_root, 0, 32);
  hdr->time = 0;
  hdr->bits = 0;
  memset(hdr->nonce, 0, 20);
  hdr->sol_size = 0;
  memset(hdr->sol, 0, sizeof(uint32_t) * 42);

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

static bool
read_sol(uint8_t **data, size_t *data_len, uint32_t *sol, uint8_t sol_size) {
#ifndef HSK_BIG_ENDIAN
  int size = ((int)sol_size) << 2;
  if (!read_bytes(data, data_len, (uint8_t *)sol, size))
    return false;
#else
  int i;
  for (i = 0; i < sol_size; i++) {
    if (!read_u32(data, data_len, sol + i))
      return false;
  }
#endif
  return true;
}

static size_t
write_sol(uint8_t **data, const uint32_t *sol, uint8_t sol_size) {
#ifndef HSK_BIG_ENDIAN
  int size = ((int)sol_size) << 2;
  return write_bytes(data, (uint8_t *)sol, size);
#else
  int i;
  for (i = 0; i < sol_size; i++)
    write_u32(data, sol[i]);
  return ((int)sol_size) << 2;
#endif
}

static bool
encode_sol(uint8_t *data, const uint32_t *sol, uint8_t sol_size) {
  return write_sol(&data, sol, sol_size);
}

bool
hsk_header_read(uint8_t **data, size_t *data_len, hsk_header_t *hdr) {
  if (!read_u32(data, data_len, &hdr->version))
    return false;

  if (!read_bytes(data, data_len, hdr->prev_block, 32))
    return false;

  if (!read_bytes(data, data_len, hdr->merkle_root, 32))
    return false;

  if (!read_bytes(data, data_len, hdr->name_root, 32))
    return false;

  if (!read_bytes(data, data_len, hdr->reserved_root, 32))
    return false;

  if (!read_u64(data, data_len, &hdr->time))
    return false;

  if (!read_u32(data, data_len, &hdr->bits))
    return false;

  if (!read_bytes(data, data_len, hdr->nonce, 20))
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
hsk_header_decode(const uint8_t *data, size_t data_len, hsk_header_t *hdr) {
  return hsk_header_read((uint8_t **)&data, &data_len, hdr);
}

int
hsk_header_write(const hsk_header_t *hdr, uint8_t **data) {
  int s = 0;
  s += write_u32(data, hdr->version);
  s += write_bytes(data, hdr->prev_block, 32);
  s += write_bytes(data, hdr->merkle_root, 32);
  s += write_bytes(data, hdr->name_root, 32);
  s += write_bytes(data, hdr->reserved_root, 32);
  s += write_u64(data, hdr->time);
  s += write_u32(data, hdr->bits);
  s += write_bytes(data, hdr->nonce, 20);
  s += write_u8(data, hdr->sol_size);
  s += write_sol(data, hdr->sol, hdr->sol_size);
  return s;
}

int
hsk_header_size(const hsk_header_t *hdr) {
  return hsk_header_write(hdr, NULL);
}

int
hsk_encode_header(const hsk_header_t *hdr, uint8_t *data) {
  return hsk_header_write(hdr, &data);
}

int
hsk_header_write_pre(const hsk_header_t *hdr, uint8_t **data) {
  int s = 0;
  s += write_u32(data, hdr->version);
  s += write_bytes(data, hdr->prev_block, 32);
  s += write_bytes(data, hdr->merkle_root, 32);
  s += write_bytes(data, hdr->name_root, 32);
  s += write_bytes(data, hdr->reserved_root, 32);
  s += write_u64(data, hdr->time);
  s += write_u32(data, hdr->bits);
  s += write_bytes(data, hdr->nonce, 20);
  return s;
}

int
hsk_header_size_pre(const hsk_header_t *hdr) {
  return hsk_header_write_pre(hdr, NULL);
}

int
hsk_header_encode_pre(const hsk_header_t *hdr, uint8_t *data) {
  return hsk_header_write_pre(hdr, &data);
}

bool
hsk_header_equal(hsk_header_t *a, hsk_header_t *b) {
  return memcmp(hsk_header_cache(a), hsk_header_cache(b), 32) == 0;
}

const uint8_t *
hsk_header_cache(hsk_header_t *hdr) {
  if (hdr->cache)
    return hdr->hash;

  int size = hsk_header_size(hdr);
  uint8_t raw[size];

  hsk_encode_header(hdr, raw);
  hsk_hash_blake2b(raw, size, hdr->hash);
  hdr->cache = true;

  return hdr->hash;
}

void
hsk_header_hash(hsk_header_t *hdr, uint8_t *hash) {
  memcpy(hash, hsk_header_cache(hdr), 32);
}

void
hsk_header_hash_pre(const hsk_header_t *hdr, uint8_t *hash) {
  int size = hsk_header_size_pre(hdr);
  uint8_t raw[size];

  hsk_header_encode_pre(hdr, raw);
  hsk_hash_blake2b(raw, size, hash);
}

void
hsk_header_hash_sol(const hsk_header_t *hdr, uint8_t *hash) {
  int size = ((int)hdr->sol_size) << 2;
  uint8_t raw[size];
  encode_sol(raw, hdr->sol, hdr->sol_size);
  hsk_hash_sha3(raw, size, hash);
}

int
hsk_header_verify_pow(const hsk_header_t *hdr) {
  uint8_t target[32];

  if (!hsk_pow_to_target(hdr->bits, target))
    return HSK_ENEGTARGET;

  int size = ((int)hdr->sol_size) << 2;

  uint8_t raw[size];
  encode_sol(raw, hdr->sol, hdr->sol_size);

  uint8_t hash[32];
  hsk_hash_sha3(raw, size, hash);

  if (memcmp(hash, target, 32) > 0)
    return HSK_EHIGHHASH;

  hsk_cuckoo_t ctx;

  assert(hsk_cuckoo_init(&ctx,
    HSK_CUCKOO_BITS,
    HSK_CUCKOO_SIZE,
    HSK_CUCKOO_PERC,
    HSK_CUCKOO_LEGACY
  ) == 0);

  size_t psize = hsk_header_size_pre(hdr);
  uint8_t pre[psize];
  hsk_header_encode_pre(hdr, pre);

  return hsk_cuckoo_verify_header(&ctx, pre, psize, hdr->sol, hdr->sol_size);
}

void
hsk_header_print(hsk_header_t *hdr, const char *prefix) {
  assert(hdr);

  char hash[65];
  char work[65];
  char prev_block[65];
  char merkle_root[65];
  char name_root[65];
  char reserved_root[65];
  char nonce[41];

  assert(hsk_hex_encode(hsk_header_cache(hdr), 32, hash));
  assert(hsk_hex_encode(hdr->work, 32, work));
  assert(hsk_hex_encode(hdr->prev_block, 32, prev_block));
  assert(hsk_hex_encode(hdr->merkle_root, 32, merkle_root));
  assert(hsk_hex_encode(hdr->name_root, 32, name_root));
  assert(hsk_hex_encode(hdr->reserved_root, 32, reserved_root));
  assert(hsk_hex_encode(hdr->nonce, 20, nonce));

  printf("%sheader\n", prefix);
  printf("%s  hash=%s\n", prefix, hash);
  printf("%s  height=%u\n", prefix, hdr->height);
  printf("%s  work=%s\n", prefix, work);
  printf("%s  version=%u\n", prefix, hdr->version);
  printf("%s  prev_block=%s\n", prefix, prev_block);
  printf("%s  merkle_root=%s\n", prefix, merkle_root);
  printf("%s  name_root=%s\n", prefix, name_root);
  printf("%s  reserved_root=%s\n", prefix, reserved_root);
  printf("%s  time=%u\n", prefix, (uint32_t)hdr->time);
  printf("%s  bits=%u\n", prefix, hdr->bits);
  printf("%s  nonce=%s\n", prefix, nonce);
  printf("%s  sol_size=%u\n", prefix, hdr->sol_size);
}
