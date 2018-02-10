#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include "hsk-error.h"
#include "bio.h"
#include "hsk-hash.h"
#include "hsk-header.h"
#include "hsk-cuckoo.h"

static bool
to_target(uint32_t bits, uint8_t *target) {
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

static bool
to_bits(uint8_t *target, uint32_t *bits) {
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
        mantissa |= (uint32_t)target[31] << 16;
      case 2:
        mantissa |= (uint32_t)target[30] << 8;
      case 1:
        mantissa |= (uint32_t)target[29];
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

static bool
read_sol(uint8_t **data, size_t *data_len, uint32_t *sol, uint8_t sol_size) {
  int32_t size = (int32_t)sol_size << 1;
#ifdef HSK_LITTLE_ENDIAN
  if (!read_bytes(data, data_len, (uint8_t *)sol, size))
    return false;
#else
  int32_t i;
  for (i = 0; i < size; i++) {
    if (!read_u32(data, data_len, sol + i))
      return false;
  }
#endif
  return true;
}

static size_t
write_sol(uint8_t **data, uint32_t *sol, uint8_t sol_size) {
  int32_t size = (int32_t)sol_size << 1;
#ifdef HSK_LITTLE_ENDIAN
  return write_bytes(data, (uint8_t *)sol, size);
#else
  int32_t i;
  for (i = 0; i < size; i++)
    write_u32(data, sol[i]);
  return size;
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

  if (!read_sol(data, data_len, hdr->sol, hdr->sol_size))
    return false;

  return true;
}

int32_t
hsk_write_header(hsk_header_t *hdr, uint8_t **data) {
  int32_t s = 0;
  s += write_u32(data, hdr->version);
  s += write_bytes(data, hdr->prev_block, 32);
  s += write_bytes(data, hdr->merkle_root, 32);
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
  s += write_bytes(data, hdr->trie_root, 32);
  s += write_u64(data, hdr->time);
  s += write_u32(data, hdr->bits);
  s += write_bytes(data, hdr->nonce, 16);
  s += write_u8(data, hdr->sol_size);
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

void
hsk_hash_header(hsk_header_t *hdr, uint8_t *hash) {
  int32_t size = hsk_size_header(hdr);
  uint8_t raw[size];

  hsk_encode_header(hdr, raw);
  hsk_blake2b(raw, size, hash);
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
  int32_t size = (int32_t)hdr->sol_size << 1;
  uint8_t raw[size];
  encode_sol(raw, hdr->sol, hdr->sol_size);
  hsk_blake2b(raw, size, hash);
}

int32_t
hsk_verify_pow(hsk_header_t *hdr) {
  uint8_t target[32];

  if (!to_target(hdr->bits, target))
    return HSK_NEGTARGET;

  int32_t size = (int32_t)hdr->sol_size << 1;

  uint8_t raw[size];
  encode_sol(raw, hdr->sol, hdr->sol_size);

  uint8_t hash[32];
  hsk_blake2b(raw, size, hash);

  if (memcmp(hash, target, 32) > 0)
    return HSK_HIGHHASH;

  hsk_cuckoo_t ctx;
  assert(hsk_cuckoo_init(&ctx, 30, 42, 50, false) == 0);

  size_t psize = hsk_size_pre(hdr);
  uint8_t pre[psize];
  hsk_encode_pre(hdr, pre);

  return hsk_cuckoo_verify_header(&ctx, pre, psize, hdr->sol, hdr->sol_size);
}

int32_t
hsk_compare_header(hsk_header_t *a, hsk_header_t *b) {
  uint8_t at[32];
  uint8_t bt[32];

  // First, take the one with
  // the lower target. Check
  // for negative targets.
  bool as = to_target(a->bits, at);
  bool bs = to_target(b->bits, bt);

  if (!as && !bs)
    return 0;

  if (!as && bs)
    return -1;

  if (as && !bs)
    return 1;

  // Compare targets (backwards).
  int32_t cmp = memcmp(bt, at, 32);

  if (cmp != 0)
    return cmp;

  // Second, try to pick the
  // lowest solution hash.
  uint8_t *ahash = at;
  uint8_t *bhash = bt;

  hsk_hash_sol(a, ahash);
  hsk_hash_sol(b, ahash);

  // Compare hashes (backwards).
  return memcmp(bhash, ahash, 32);
}
