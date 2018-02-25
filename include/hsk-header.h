#ifndef _HSK_HEADER_H
#define _HSK_HEADER_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct hsk_header_s {
  uint32_t version;
  uint8_t prev_block[32];
  uint8_t merkle_root[32];
  uint8_t witness_root[32];
  uint8_t trie_root[32];
  uint64_t time;
  uint32_t bits;
  uint8_t nonce[16];
  uint8_t sol_size;
  uint32_t sol[42];

  bool cache;
  uint8_t hash[32];
  uint32_t height;
  uint8_t work[32];

  struct hsk_header_s *next;
} hsk_header_t;

void
hsk_header_init(hsk_header_t *hdr);

hsk_header_t *
hsk_header_alloc(void);

hsk_header_t *
hsk_header_clone(hsk_header_t *hdr);

bool
hsk_pow_to_target(uint32_t bits, uint8_t *target);

bool
hsk_pow_to_bits(uint8_t *target, uint32_t *bits);

bool
hsk_header_get_proof(hsk_header_t *hdr, uint8_t *proof);

bool
hsk_header_calc_work(hsk_header_t *hdr, hsk_header_t *prev);

bool
hsk_header_read(uint8_t **data, size_t *data_len, hsk_header_t *hdr);

bool
hsk_header_decode(uint8_t *data, size_t data_len, hsk_header_t *hdr);

int32_t
hsk_header_write(hsk_header_t *hdr, uint8_t **data);

int32_t
hsk_header_size(hsk_header_t *hdr);

int32_t
hsk_header_encode(hsk_header_t *hdr, uint8_t *data);

int32_t
hsk_header_write_pre(hsk_header_t *hdr, uint8_t **data);

int32_t
hsk_header_size_pre(hsk_header_t *hdr);

int32_t
hsk_header_encode_pre(hsk_header_t *hdr, uint8_t *data);

bool
hsk_header_equal(hsk_header_t *a, hsk_header_t *b);

uint8_t *
hsk_header_cache(hsk_header_t *hdr);

void
hsk_header_hash(hsk_header_t *hdr, uint8_t *hash);

void
hsk_header_hash_pre(hsk_header_t *hdr, uint8_t *hash);

int32_t
hsk_header_hash_sol(hsk_header_t *hdr, uint8_t *hash);

int32_t
hsk_header_verify_pow(hsk_header_t *hdr);
#endif
