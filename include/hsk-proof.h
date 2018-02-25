#ifndef _HSK_PROOF_H
#define _HSK_PROOF_H

#include <stdint.h>
#include <stdbool.h>

// Node types
#define HSK_NULLNODE 0
#define HSK_HASHNODE 1
#define HSK_SHORTNODE 2
#define HSK_FULLNODE 3
#define HSK_VALUENODE 4

// Proofs
typedef struct _raw_node {
  uint8_t *data;
  size_t data_len;
  struct _raw_node *next;
} hsk_raw_node_t;

typedef struct {
  uint8_t block_hash[32];
  hsk_raw_node_t *nodes;
  uint8_t *data;
  size_t data_len;
} hsk_proof_t;

// Node types
typedef struct {
  uint8_t type;
} hsk_node_t;

typedef struct {
  uint8_t type;
} hsk_nullnode_t;

typedef struct {
  uint8_t type;
  uint8_t data[32];
} hsk_hashnode_t;

typedef struct {
  uint8_t type;
  uint8_t *key;
  size_t key_len;
  hsk_node_t *value;
} hsk_shortnode_t;

typedef struct {
  uint8_t type;
  hsk_node_t *children[17];
} hsk_fullnode_t;

typedef struct {
  uint8_t type;
  uint8_t *data;
  size_t data_len;
} hsk_valuenode_t;

int32_t
hsk_proof_verify(
  uint8_t *root,
  uint8_t *key,
  hsk_raw_node_t *nodes,
  uint8_t **data,
  size_t *data_len
);

int32_t
hsk_proof_verify_name(
  uint8_t *root,
  char *name,
  hsk_raw_node_t *nodes,
  uint8_t **data,
  size_t *data_len
);

void
hsk_raw_node_init(hsk_raw_node_t *n);

hsk_raw_node_t *
hsk_raw_node_alloc();

void
hsk_raw_node_free(hsk_raw_node_t *n);

void
hsk_raw_node_free_list(hsk_raw_node_t *n);

void
hsk_proof_init(hsk_proof_t *p);

hsk_proof_t *
hsk_proof_alloc();

void
hsk_proof_free(hsk_proof_t *p);
#endif
