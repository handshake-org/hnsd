#ifndef _HSK_PROOF_H
#define _HSK_PROOF_H

#include <stdint.h>
#include <stdbool.h>

#define HSK_PROOF_DEADEND 0
#define HSK_PROOF_SHORT 1
#define HSK_PROOF_COLLISION 2
#define HSK_PROOF_EXISTS 3
#define HSK_PROOF_UNKNOWN 4

typedef struct hsk_proof_node_s {
  uint8_t prefix[32];
  uint16_t prefix_size;
  uint8_t node[32];
} hsk_proof_node_t;

typedef struct hsk_proof_s {
  uint8_t type;
  uint16_t depth;
  hsk_proof_node_t *nodes;
  uint16_t node_count;
  uint8_t *prefix;
  uint16_t prefix_size;
  uint8_t *left;
  uint8_t *right;
  uint8_t *nx_key;
  uint8_t *nx_hash;
  uint8_t *value;
  uint16_t value_size;
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
