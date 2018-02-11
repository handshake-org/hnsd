#ifndef _HSK_HEADER_H
#define _HSK_HEADER_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
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
} hsk_header_t;

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

void
hsk_hash_header(hsk_header_t *hdr, uint8_t *hash);

void
hsk_hash_pre(hsk_header_t *hdr, uint8_t *hash);

int32_t
hsk_hash_sol(hsk_header_t *hdr, uint8_t *hash);

int32_t
hsk_verify_pow(hsk_header_t *hdr);

int32_t
hsk_compare_header(hsk_header_t *a, hsk_header_t *b);
#endif
