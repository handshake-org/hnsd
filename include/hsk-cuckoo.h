#ifndef _HSK_CUCKOO_H
#define _HSK_CUCKOO_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct {
  uint64_t nodes;
  uint32_t mask;
  uint8_t size;
  uint64_t easiness;
  bool legacy;
} hsk_cuckoo_t;

int32_t
hsk_cuckoo_init(hsk_cuckoo_t *ctx, int32_t bits, int32_t size, int32_t ease, bool legacy);

int32_t
hsk_cuckoo_sipkey(hsk_cuckoo_t *ctx, uint8_t *hdr, size_t hdr_len, uint8_t *key);

uint32_t
hsk_cuckoo_sipnode(hsk_cuckoo_t *ctx, uint8_t *key, uint32_t nonce, int32_t uorv);

int32_t
hsk_cuckoo_verify(hsk_cuckoo_t *ctx, uint8_t *key, uint32_t *nonces);

int32_t
hsk_cuckoo_verify_header(
  hsk_cuckoo_t *ctx,
  uint8_t *hdr,
  size_t hdr_len,
  uint32_t *sol,
  size_t sol_size
);
#endif
