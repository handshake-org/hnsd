#ifndef _HSK_CUCKOO_H
#define _HSK_CUCKOO_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct {
  uint64_t nodes;
  uint32_t mask;
  uint32_t size;
  uint64_t easiness;
  bool legacy;
} hsk_cuckoo_t;

int
hsk_cuckoo_init(
  hsk_cuckoo_t *ctx,
  int bits,
  int size,
  int perc,
  bool legacy
);

int
hsk_cuckoo_sipkey(
  const hsk_cuckoo_t *ctx,
  const uint8_t *hdr,
  size_t hdr_len,
  uint8_t *key
);

uint32_t
hsk_cuckoo_sipnode(
  const hsk_cuckoo_t *ctx,
  const uint8_t *key,
  uint32_t nonce,
  int uorv
);

int
hsk_cuckoo_verify(
  const hsk_cuckoo_t *ctx,
  const uint8_t *key,
  const uint32_t *nonces
);

int
hsk_cuckoo_verify_header(
  const hsk_cuckoo_t *ctx,
  const uint8_t *hdr,
  size_t hdr_len,
  const uint32_t *sol,
  size_t sol_size
);
#endif
