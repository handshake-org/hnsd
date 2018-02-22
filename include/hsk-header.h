#ifndef _HSK_HEADER_H
#define _HSK_HEADER_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct hsk_header {
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

  struct hsk_header *next;
} hsk_header_t;

bool
hsk_to_target(uint32_t bits, uint8_t *target);

bool
hsk_to_bits(uint8_t *target, uint32_t *bits);

bool
hsk_get_proof2(uint32_t bits, uint8_t *proof);

bool
hsk_get_work(uint8_t *prev, uint32_t bits, uint8_t *work);

bool
hsk_read_header(uint8_t **data, size_t *data_len, hsk_header_t *hdr);

bool
hsk_decode_header(uint8_t *data, size_t data_len, hsk_header_t *hdr);

int32_t
hsk_write_header(hsk_header_t *hdr, uint8_t **data);

int32_t
hsk_size_header(hsk_header_t *hdr);

int32_t
hsk_encode_header(hsk_header_t *hdr, uint8_t *data);

int32_t
hsk_write_pre(hsk_header_t *hdr, uint8_t **data);

int32_t
hsk_size_pre(hsk_header_t *hdr);

int32_t
hsk_encode_pre(hsk_header_t *hdr, uint8_t *data);

bool
hsk_header_equal(hsk_header_t *a, hsk_header_t *b);

uint8_t *
hsk_cache_header(hsk_header_t *hdr);

void
hsk_hash_header(hsk_header_t *hdr, uint8_t *hash);

void
hsk_hash_pre(hsk_header_t *hdr, uint8_t *hash);

int32_t
hsk_hash_sol(hsk_header_t *hdr, uint8_t *hash);

int32_t
hsk_verify_pow(hsk_header_t *hdr);
#endif
