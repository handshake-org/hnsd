#ifndef _HSK_CHAIN
#define _HSK_CHAIN

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include "hsk-map.h"
#include "hsk-header.h"
#include "hsk-timedata.h"

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
hsk_chain_init(hsk_chain_t *chain, hsk_timedata_t *td);

void
hsk_chain_uninit(hsk_chain_t *chain);

hsk_chain_t *
hsk_chain_alloc(hsk_timedata_t *td);

void
hsk_chain_free(hsk_chain_t *chain);

bool
hsk_chain_synced(hsk_chain_t *chain);

int32_t
hsk_chain_add(hsk_chain_t *chain, hsk_header_t *h);
#endif
