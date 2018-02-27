#ifndef _HSK_TIMEDATA_H
#define _HSK_TIMEDATA_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include "hsk-map.h"
#include "hsk-addr.h"

#define HSK_TIMEDATA_LIMIT 200

typedef struct hsk_timedata_s {
  size_t sample_len;
  int64_t samples[HSK_TIMEDATA_LIMIT];
  hsk_map_t known;
  int64_t offset;
  bool checked;
} hsk_timedata_t;

int32_t
hsk_timedata_init(hsk_timedata_t *td);

void
hsk_timedata_uninit(hsk_timedata_t *td);

hsk_timedata_t *
hsk_timedata_alloc(void);

void
hsk_timedata_free(hsk_timedata_t *td);

int32_t
hsk_timedata_add(hsk_timedata_t *td, hsk_addr_t *addr, int64_t time);

int64_t
hsk_timedata_now(hsk_timedata_t *td);

int64_t
hsk_timedata_adjust(hsk_timedata_t *td, int64_t time);

int64_t
hsk_timedata_local(hsk_timedata_t *td, int64_t time);

int64_t
hsk_timedata_ms(hsk_timedata_t *td);
#endif
