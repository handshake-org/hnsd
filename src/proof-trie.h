#ifndef _HSK_PROOF_H
#define _HSK_PROOF_H

#include <stdint.h>
#include <stdbool.h>

#define HSK_PROOF_DEADEND 0
#define HSK_PROOF_COLLISION 1
#define HSK_PROOF_EXISTS 2
#define HSK_PROOF_UNKNOWN 3

typedef struct hsk_proof_s {
  uint8_t type;
  uint8_t *nodes;
  uint16_t node_count;
  uint8_t *value;
  uint16_t value_size;
  uint8_t *nx_key;
  uint8_t *nx_hash;
} hsk_proof_t;

void
hsk_proof_init(hsk_proof_t *proof);

hsk_proof_t *
hsk_proof_alloc(void);

void
hsk_proof_uninit(hsk_proof_t *proof);

void
hsk_proof_free(hsk_proof_t *proof);

bool
hsk_proof_read(uint8_t **data, size_t *data_len, hsk_proof_t *proof);

bool
hsk_proof_decode(const uint8_t *data, size_t data_len, hsk_proof_t *proof);

int
hsk_proof_verify(
  const uint8_t *root,
  const uint8_t *key,
  const hsk_proof_t *proof,
  bool *exists,
  uint8_t **data,
  size_t *data_len
);
#endif
