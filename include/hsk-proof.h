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
  size_t len;
  struct _raw_node *next;
} hsk_raw_node_t;

typedef struct {
  uint8_t *block_hash;
  hsk_raw_node_t *nodes;
  hsk_raw_node_t *data;
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
  int32_t key_len;
  hsk_node_t *value;
} hsk_shortnode_t;

typedef struct {
  uint8_t type;
  hsk_node_t *children[17];
} hsk_fullnode_t;

typedef struct {
  uint8_t type;
  uint8_t *data;
  int32_t data_len;
} hsk_valuenode_t;

// Cuckoo cycle
int32_t
hsk_parse_node(
  uint8_t *data,
  size_t data_len,
  hsk_node_t **node,
  uint8_t **ret_data,
  size_t *ret_len
);

void
hsk_free_node(hsk_node_t *node, bool recurse);

int32_t
hsk_verify_proof(
  uint8_t *root,
  uint8_t *key,
  hsk_raw_node_t *nodes,
  uint8_t **data,
  size_t *data_len
);

int32_t
hsk_verify_name(
  uint8_t *root,
  char *name,
  hsk_raw_node_t *nodes,
  uint8_t **data,
  size_t *data_len
);
#endif
