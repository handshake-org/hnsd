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
  hsk_header_t *tip;
  hsk_header_t *genesis;
  bool synced;
  hsk_timedata_t *td;
  hsk_map_t hashes;
  hsk_map_t heights;
  hsk_map_t orphans;
  hsk_map_t prevs;
} hsk_chain_t;

/*
 * Chain
 */

int32_t
hsk_chain_init(hsk_chain_t *chain, const hsk_timedata_t *td);

void
hsk_chain_uninit(hsk_chain_t *chain);

hsk_chain_t *
hsk_chain_alloc(const hsk_timedata_t *td);

void
hsk_chain_free(hsk_chain_t *chain);

bool
hsk_chain_has(const hsk_chain_t *chain, const uint8_t *hash);

hsk_header_t *
hsk_chain_get(const hsk_chain_t *chain, const uint8_t *hash);

hsk_header_t *
hsk_chain_get_by_height(const hsk_chain_t *chain, int32_t height);

bool
hsk_chain_has_orphan(const hsk_chain_t *chain, const uint8_t *hash);

hsk_header_t *
hsk_chain_get_orphan(const hsk_chain_t *chain, const uint8_t *hash);

hsk_header_t *
hsk_chain_get_ancestor(
  const hsk_chain_t *chain,
  const hsk_header_t *hdr,
  int32_t height
);

bool
hsk_chain_synced(const hsk_chain_t *chain);

int32_t
hsk_chain_add(hsk_chain_t *chain, const hsk_header_t *h);
#endif
