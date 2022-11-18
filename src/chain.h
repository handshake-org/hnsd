#ifndef _HSK_CHAIN
#define _HSK_CHAIN

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include "map.h"
#include "header.h"
#include "timedata.h"

/*
 * Types
 */

typedef struct hsk_chain_s {
  int64_t height;
  uint32_t init_height;
  hsk_header_t *tip;
  hsk_header_t *genesis;
  bool synced;
  hsk_timedata_t *td;
  hsk_map_t hashes;
  hsk_map_t heights;
  hsk_map_t orphans;
  hsk_map_t prevs;
  char *prefix;
} hsk_chain_t;

/*
 * Chain
 */

int
hsk_chain_init(hsk_chain_t *chain, const hsk_timedata_t *td);

void
hsk_chain_uninit(hsk_chain_t *chain);

void
hsk_chain_free(hsk_chain_t *chain);

bool
hsk_chain_has(const hsk_chain_t *chain, const uint8_t *hash);

hsk_header_t *
hsk_chain_get(const hsk_chain_t *chain, const uint8_t *hash);

hsk_header_t *
hsk_chain_get_by_height(const hsk_chain_t *chain, uint32_t height);

bool
hsk_chain_has_orphan(const hsk_chain_t *chain, const uint8_t *hash);

hsk_header_t *
hsk_chain_get_orphan(const hsk_chain_t *chain, const uint8_t *hash);

const uint8_t *
hsk_chain_safe_root(const hsk_chain_t *chain);

hsk_header_t *
hsk_chain_get_ancestor(
  const hsk_chain_t *chain,
  const hsk_header_t *hdr,
  uint32_t height
);

float
hsk_chain_progress(const hsk_chain_t *chain);

bool
hsk_chain_synced(const hsk_chain_t *chain);

int
hsk_chain_add(hsk_chain_t *chain, const hsk_header_t *h);

int
hsk_chain_save(
  hsk_chain_t *chain,
  hsk_header_t *hdr
);

#endif
