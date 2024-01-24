#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "bn.h"
#include "chain.h"
#include "constants.h"
#include "error.h"
#include "header.h"
#include "map.h"
#include "msg.h"
#include "store.h"
#include "timedata.h"
#include "utils.h"

/*
 * Prototypes
 */

static int
hsk_chain_init_genesis(hsk_chain_t *chain);

static int
hsk_chain_insert(
  hsk_chain_t *chain,
  hsk_header_t *hdr,
  const hsk_header_t *prev
);

static void
hsk_chain_maybe_sync(hsk_chain_t *chain);

static void
hsk_chain_checkpoint_flush(hsk_chain_t *chain);

/*
 * Helpers
 */

static int
qsort_cmp(const void *a, const void *b) {
  int64_t x = *((int64_t *)a);
  int64_t y = *((int64_t *)b);

  if (x < y)
    return -1;

  if (x > y)
    return 1;

  return 0;
}

/*
 * Chain
 */


static void
hsk_chain_log(const hsk_chain_t *chain, const char *fmt, ...) {
  printf("chain (%u): ", (uint32_t)chain->height);

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

int
hsk_chain_init(hsk_chain_t *chain, const hsk_timedata_t *td) {
  if (!chain || !td)
    return HSK_EBADARGS;

  chain->height = 0;
  chain->tip = NULL;
  chain->genesis = NULL;
  chain->synced = false;
  chain->td = (hsk_timedata_t *)td;
  chain->prefix = NULL;

  hsk_map_init_hash_map(&chain->hashes, free);
  hsk_map_init_int_map(&chain->heights, NULL);
  hsk_map_init_hash_map(&chain->orphans, free);
  hsk_map_init_hash_map(&chain->prevs, NULL);

  return hsk_chain_init_genesis(chain);
}

static int
hsk_chain_init_genesis(hsk_chain_t *chain) {
  if (!chain)
    return HSK_EBADARGS;

  hsk_header_t *tip = hsk_header_alloc();

  if (!tip)
    return HSK_ENOMEM;

  uint8_t *data = (uint8_t *)HSK_GENESIS;

  assert(hsk_header_decode(data, HSK_HEADER_SIZE, tip));
  assert(hsk_header_calc_work(tip, NULL));

  if (!hsk_map_set(&chain->hashes, hsk_header_cache(tip), tip)) {
    free(tip);
    return HSK_ENOMEM;
  }

  if (!hsk_map_set(&chain->heights, &tip->height, tip)) {
    hsk_map_del(&chain->hashes, hsk_header_cache(tip));
    free(tip);
    return HSK_ENOMEM;
  }

  chain->height = tip->height;
  chain->init_height = tip->height;
  chain->tip = tip;
  chain->genesis = tip;

  hsk_chain_maybe_sync(chain);

  return HSK_SUCCESS;
}

void
hsk_chain_uninit(hsk_chain_t *chain) {
  if (!chain)
    return;

  hsk_map_uninit(&chain->heights);
  hsk_map_uninit(&chain->hashes);
  hsk_map_uninit(&chain->prevs);
  hsk_map_uninit(&chain->orphans);

  chain->tip = NULL;
  chain->genesis = NULL;
}

void
hsk_chain_free(hsk_chain_t *chain) {
  if (!chain)
    return;

  hsk_chain_uninit(chain);
  free(chain);
}

bool
hsk_chain_has(const hsk_chain_t *chain, const uint8_t *hash) {
  return hsk_map_has(&chain->hashes, hash);
}

hsk_header_t *
hsk_chain_get(const hsk_chain_t *chain, const uint8_t *hash) {
  return hsk_map_get(&chain->hashes, hash);
}

hsk_header_t *
hsk_chain_get_by_height(const hsk_chain_t *chain, uint32_t height) {
  return hsk_map_get(&chain->heights, &height);
}

bool
hsk_chain_has_orphan(const hsk_chain_t *chain, const uint8_t *hash) {
  return hsk_map_has(&chain->orphans, hash);
}

hsk_header_t *
hsk_chain_get_orphan(const hsk_chain_t *chain, const uint8_t *hash) {
  return hsk_map_get(&chain->orphans, hash);
}

const uint8_t *
hsk_chain_safe_root(const hsk_chain_t *chain) {
  // The tree is committed on an interval.
  // Mainnet is 72 blocks, meaning at height 72,
  // the name set of the past 72 blocks are
  // inserted into the tree. The commitment for
  // that insertion actually appears in a block
  // header one block later (height 73). We
  // want the the root _before_ the current one
  // so we can calculate that with:
  //   chain_height - (chain_height % interval)

  uint32_t interval = HSK_TREE_INTERVAL;
  uint32_t mod = (uint32_t)chain->height % interval;

  // If there's enough proof-of-work
  // on top of the most recent root,
  // it should be safe to use it.
  if (mod >= 12)
    mod = 0;

  uint32_t height = (uint32_t)chain->height - mod;

  hsk_header_t *prev = hsk_chain_get_by_height(chain, height);
  assert(prev);

  hsk_chain_log(chain,
    "using safe height of %u for resolution\n",
    height);

  return prev->name_root;
}

static hsk_header_t *
hsk_chain_resolve_orphan(hsk_chain_t *chain, const uint8_t *hash) {
  hsk_header_t *orphan = hsk_map_get(&chain->prevs, hash);

  if (!orphan)
    return NULL;

  hsk_map_del(&chain->prevs, orphan->prev_block);
  hsk_map_del(&chain->orphans, hsk_header_cache(orphan));

  return orphan;
}

hsk_header_t *
hsk_chain_get_ancestor(
  const hsk_chain_t *chain,
  const hsk_header_t *hdr,
  uint32_t height
) {
  assert(height >= 0);
  assert(height <= hdr->height);

  hsk_header_t *h = (hsk_header_t *)hdr;

  while (h->height != height) {
    h = hsk_map_get(&chain->hashes, h->prev_block);
    assert(h);
  }

  return h;
}

static bool
hsk_chain_has_work(const hsk_chain_t *chain) {
  return memcmp(chain->tip->work, HSK_CHAINWORK, 32) >= 0;
}

static void
hsk_chain_maybe_sync(hsk_chain_t *chain) {
  if (chain->synced)
    return;

  int64_t now = hsk_timedata_now(chain->td);

  if (((int64_t)chain->tip->time) < now - HSK_MAX_TIP_AGE)
    return;

  if (!hsk_chain_has_work(chain))
    return;

  hsk_chain_log(chain, "chain is fully synced\n");
  chain->synced = true;
}

float
hsk_chain_progress(const hsk_chain_t *chain) {
  uint64_t start = chain->genesis->time;
  uint64_t current = chain->tip->time - start;
  uint64_t end = hsk_timedata_now(chain->td) - start - (40 * 60);
  float progress = (float)current / end;

  if (progress > 1)
    return 1;

  return progress;
}

bool
hsk_chain_synced(const hsk_chain_t *chain) {
  return chain->synced;
}

static void
hsk_chain_checkpoint_flush(hsk_chain_t *chain) {
  // Setting is off
  if (!chain->prefix)
    return;

  // Skip first window after init to avoid re-writing the same checkpoint
  if (chain->height - chain->init_height <= HSK_STORE_CHECKPOINT_WINDOW)
    return;

  hsk_store_write(chain);
}

void
hsk_chain_get_locator(const hsk_chain_t *chain, hsk_getheaders_msg_t *msg) {
  assert(chain && msg);

  int i = 0;
  hsk_header_t *tip = chain->tip;
  int64_t height = chain->height;
  int64_t step = 1;

  hsk_header_hash(tip, msg->hashes[i++]);

  while (height > 0) {
    height -= step;

    if (height < 0)
      height = 0;

    if (i > 10)
      step *= 2;

    if (i == sizeof(msg->hashes) - 1)
      height = 0;

    hsk_header_t *hdr = hsk_chain_get_by_height(chain, (uint32_t)height);

    // Due to checkpoint initialization
    // we may not have any headers from here
    // down to genesis
    if (!hdr)
      continue;

    hsk_header_hash(hdr, msg->hashes[i++]);
  }

  msg->hash_count = i;
}

static int64_t
hsk_chain_get_mtp(const hsk_chain_t *chain, const hsk_header_t *prev) {
  assert(chain);

  if (!prev)
    return 0;

  int timespan = 11;
  int64_t median[11];
  size_t size = 0;
  int i;

  for (i = 0; i < timespan && prev; i++) {
    median[i] = (int64_t)prev->time;
    prev = hsk_map_get(&chain->hashes, prev->prev_block);
    size += 1;
  }

  qsort((void *)median, size, sizeof(int64_t), qsort_cmp);

  return median[size >> 1];
}

static void
hsk_header_swap(hsk_header_t **x, hsk_header_t **y) {
  hsk_header_t *z = *x;
  *x = *y;
  *y = z;
}

static hsk_header_t *
hsk_chain_suitable_block(const hsk_chain_t *chain, const hsk_header_t *prev) {
  hsk_header_t *z = (hsk_header_t *)prev;
  assert(z);

  hsk_header_t *y = hsk_map_get(&chain->hashes, z->prev_block);
  assert(y);

  hsk_header_t *x = hsk_map_get(&chain->hashes, y->prev_block);
  assert(x);

  if (x->time > z->time)
    hsk_header_swap(&x, &z);

  if (x->time > y->time)
    hsk_header_swap(&x, &y);

  if (y->time > z->time)
    hsk_header_swap(&y, &z);

  return y;
}

static uint32_t
hsk_chain_retarget(const hsk_chain_t *chain,
                   const hsk_header_t *first,
                   const hsk_header_t *last) {
  assert(chain && first && last);
  assert(last->height >= first->height);

  uint8_t *limit = (uint8_t *)HSK_LIMIT;

  hsk_bn_t target_bn;
  hsk_bn_t last_bn;
  hsk_bn_t spacing_bn;
  hsk_bn_t actual_bn;
  hsk_bn_t max_bn;
  hsk_bn_t limit_bn;

  uint8_t target[32];
  uint32_t cmpct;

  hsk_bn_from_array(&target_bn, first->work, 32);
  hsk_bn_from_array(&last_bn, last->work, 32);

  hsk_bn_from_int(&spacing_bn, (uint64_t)HSK_TARGET_SPACING);

  hsk_bn_sub(&last_bn, &target_bn, &target_bn);
  hsk_bn_mul(&target_bn, &spacing_bn, &target_bn);

  int64_t actual = last->time - first->time;

  if (actual < HSK_MIN_ACTUAL)
    actual = HSK_MIN_ACTUAL;

  if (actual > HSK_MAX_ACTUAL)
    actual = HSK_MAX_ACTUAL;

  hsk_bn_from_int(&actual_bn, (uint64_t)actual);

  hsk_bn_div(&target_bn, &actual_bn, &target_bn);

  if (hsk_bn_is_zero(&target_bn))
    return HSK_BITS;

  hsk_bn_t one_bn;
  hsk_bn_from_int(&one_bn, 1);

  hsk_bn_from_int(&max_bn, 1);
  hsk_bn_lshift(&max_bn, &max_bn, 256);

  hsk_bn_div(&max_bn, &target_bn, &target_bn);
  hsk_bn_sub(&target_bn, &one_bn, &target_bn);

  hsk_bn_from_array(&limit_bn, limit, 32);

  if (hsk_bn_cmp(&target_bn, &limit_bn) > 0)
    return HSK_BITS;

  hsk_bn_to_array(&target_bn, target, 32);

  assert(hsk_pow_to_bits(target, &cmpct));

  return cmpct;
}

static uint32_t
hsk_chain_get_target(
  const hsk_chain_t *chain,
  int64_t time,
  const hsk_header_t *prev
) {
  assert(chain);

  // Genesis
  if (!prev) {
    assert(time == chain->genesis->time);
    return HSK_BITS;
  }

  if (HSK_NO_RETARGETTING)
    return HSK_BITS;

  if (HSK_TARGET_RESET) {
    // Special behavior for testnet:
    if (time > (int64_t)prev->time + HSK_TARGET_SPACING * 2)
      return HSK_BITS;
   }

  if (prev->height < 144 + 2)
    return HSK_BITS;

  hsk_header_t *last = hsk_chain_suitable_block(chain, prev);

  int64_t height = prev->height - 144;
  hsk_header_t *ancestor = hsk_chain_get_ancestor(chain, prev, height);
  hsk_header_t *first = hsk_chain_suitable_block(chain, ancestor);

  return hsk_chain_retarget(chain, first, last);
}

static hsk_header_t *
hsk_chain_find_fork(
  const hsk_chain_t *chain,
  hsk_header_t *fork,
  hsk_header_t *longer
) {
  assert(chain && fork && longer);

  while (!hsk_header_equal(fork, longer)) {
    while (longer->height > fork->height) {
      longer = hsk_map_get(&chain->hashes, longer->prev_block);
      if (!longer)
        return NULL;
    }

    if (hsk_header_equal(fork, longer))
      return fork;

    fork = hsk_map_get(&chain->hashes, fork->prev_block);

    if (!fork)
      return NULL;
  }

  return fork;
}

static void
hsk_chain_reorganize(hsk_chain_t *chain, hsk_header_t *competitor) {
  assert(chain && competitor);

  hsk_header_t *tip = chain->tip;
  hsk_header_t *fork = hsk_chain_find_fork(chain, tip, competitor);

  assert(fork);

  // Blocks to disconnect.
  hsk_header_t *disconnect = NULL;
  hsk_header_t *entry = tip;
  hsk_header_t *tail = NULL;
  while (!hsk_header_equal(entry, fork)) {
    assert(!entry->next);

    if (!disconnect)
      disconnect = entry;

    if (tail)
      tail->next = entry;

    tail = entry;

    entry = hsk_map_get(&chain->hashes, entry->prev_block);
    assert(entry);
  }

  // Blocks to connect.
  entry = competitor;
  hsk_header_t *connect = NULL;
  while (!hsk_header_equal(entry, fork)) {
    assert(!entry->next);

    // Build the list backwards.
    if (connect)
      entry->next = connect;

    connect = entry;

    entry = hsk_map_get(&chain->hashes, entry->prev_block);
    assert(entry);
  }

  // Disconnect blocks.
  hsk_header_t *c, *n;
  for (c = disconnect; c; c = n) {
    n = c->next;
    c->next = NULL;
    hsk_map_del(&chain->heights, &c->height);
  }

  // Connect blocks (backwards, save last).
  for (c = connect; c; c = n) {
    n = c->next;
    c->next = NULL;

    if (!n) // halt on last
      break;

    assert(hsk_map_set(&chain->heights, &c->height, (void *)c));
  }
}

int
hsk_chain_add(hsk_chain_t *chain, const hsk_header_t *h) {
  if (!chain || !h)
    return HSK_EBADARGS;

  int rc = HSK_SUCCESS;
  hsk_header_t *hdr = hsk_header_clone(h);

  if (!hdr) {
    rc = HSK_ENOMEM;
    goto fail;
  }

  const uint8_t *hash = hsk_header_cache(hdr);

  hsk_chain_log(chain, "adding block: %s\n", hsk_hex_encode32(hash));
  hsk_chain_log(chain, "tree_root %s timestamp %d \n",
      hsk_hex_encode32(hdr->name_root), hdr->time);

  int64_t now = hsk_timedata_now(chain->td);

  if (hdr->time > now + 2 * 60 * 60) {
    hsk_chain_log(chain, "  rejected: time-too-new\n");
    rc = HSK_ETIMETOONEW;
    goto fail;
  }

  if (hsk_map_has(&chain->hashes, hash)) {
    hsk_chain_log(chain, "  rejected: duplicate\n");
    rc = HSK_EDUPLICATE;
    goto fail;
  }

  if (hsk_map_has(&chain->orphans, hash)) {
    hsk_chain_log(chain, "  rejected: duplicate-orphan\n");
    rc = HSK_EDUPLICATEORPHAN;
    goto fail;
  }

  rc = hsk_header_verify_pow(hdr);

  if (rc != HSK_SUCCESS) {
    hsk_chain_log(chain, "  rejected: pow error: %s\n", hsk_strerror(rc));
    goto fail;
  }

  hsk_header_t *prev = hsk_chain_get(chain, hdr->prev_block);

  if (!prev) {
    hsk_chain_log(chain, "  stored as orphan\n");

    if (chain->orphans.size > 10000) {
      hsk_chain_log(chain, "clearing orphans: %d\n", chain->orphans.size);
      hsk_map_clear(&chain->prevs);
      hsk_map_clear(&chain->orphans);
    }

    if (!hsk_map_set(&chain->orphans, hash, (void *)hdr)) {
      rc = HSK_ENOMEM;
      goto fail;
    }

    if (!hsk_map_set(&chain->prevs, hdr->prev_block, (void *)hdr)) {
      hsk_map_del(&chain->orphans, hash);
      rc = HSK_ENOMEM;
      goto fail;
    }

    return HSK_EORPHAN;
  }

  rc = hsk_chain_insert(chain, hdr, prev);

  if (rc != HSK_SUCCESS)
    goto fail;

  for (;;) {
    prev = hdr;
    hdr = hsk_chain_resolve_orphan(chain, hash);

    if (!hdr)
      break;

    hash = hsk_header_cache(hdr);

    rc = hsk_chain_insert(chain, hdr, prev);

    hsk_chain_log(chain, "resolved orphan: %s\n", hsk_hex_encode32(hash));

    if (rc != HSK_SUCCESS) {
      free(hdr);
      return rc;
    }
  }

  return rc;

fail:
  if (hdr)
    free(hdr);

  return rc;
}

static int
hsk_chain_insert(
  hsk_chain_t *chain,
  hsk_header_t *hdr,
  const hsk_header_t *prev
) {
  const uint8_t *hash = hsk_header_cache(hdr);
  int64_t mtp = hsk_chain_get_mtp(chain, prev);

  if ((int64_t)hdr->time <= mtp) {
    hsk_chain_log(chain, "  rejected: time-too-old\n");
    return HSK_ETIMETOOOLD;
  }

  uint32_t bits = hsk_chain_get_target(chain, hdr->time, prev);

  if (hdr->bits != bits) {
    hsk_chain_log(chain,
      "  rejected: bad-diffbits: %x != %x\n",
      hdr->bits, bits);
    return HSK_EBADDIFFBITS;
  }

  hdr->height = prev->height + 1;

  assert(hsk_header_calc_work(hdr, prev));

  // Less work than chain tip, this header is on a fork
  if (memcmp(hdr->work, chain->tip->work, 32) <= 0) {
    if (!hsk_map_set(&chain->hashes, hash, (void *)hdr))
      return HSK_ENOMEM;

    hsk_chain_log(chain, "  stored on alternate chain\n");
  } else {
    // More work than tip, but does not connect to tip: we have a reorg
    if (memcmp(hdr->prev_block, hsk_header_cache(chain->tip), 32) != 0) {
      hsk_chain_log(chain, "  reorganizing...\n");
      hsk_chain_reorganize(chain, hdr);
    }

    return hsk_chain_save(chain, hdr);
  }

  return HSK_SUCCESS;
}

int
hsk_chain_save(
  hsk_chain_t *chain,
  hsk_header_t *hdr
) {
    // Save the header
    if (!hsk_map_set(&chain->hashes, &hdr->hash, (void *)hdr))
      return HSK_ENOMEM;

    if (!hsk_map_set(&chain->heights, &hdr->height, (void *)hdr)) {
      hsk_map_del(&chain->hashes, &hdr->hash);
      return HSK_ENOMEM;
    }

    // Set the chain tip
    chain->height = hdr->height;
    chain->tip = hdr;

    hsk_chain_log(chain, "  added to main chain\n");
    hsk_chain_log(chain, "  new height: %u\n", (uint32_t)chain->height);

    hsk_chain_maybe_sync(chain);

    // Save batch of headers to disk
    if (chain->height % HSK_STORE_CHECKPOINT_WINDOW == 0)
      hsk_chain_checkpoint_flush(chain);

    return HSK_SUCCESS;
}
