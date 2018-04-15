#ifndef _HSK_PROOF_H
#define _HSK_PROOF_H

#include <stdint.h>
#include <stdbool.h>

#define HSK_NULLNODE 0
#define HSK_HASHNODE 1
#define HSK_SHORTNODE 2
#define HSK_FULLNODE 3
#define HSK_VALUENODE 4

typedef struct hsk_raw_node_s {
  uint8_t *data;
  size_t data_len;
  struct hsk_raw_node_s *next;
} hsk_raw_node_t;

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
  const uint8_t *root,
  const uint8_t *key,
  const hsk_raw_node_t *nodes,
  bool *exists,
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
#endif
