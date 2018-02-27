#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>

#include "hsk-addr.h"
#include "hsk-error.h"
#include "hsk-map.h"
#include "hsk-timedata.h"
#include "utils.h"

int32_t
hsk_timedata_init(hsk_timedata_t *td) {
  if (!td)
    return HSK_EBADARGS;

  td->sample_len = 0;
  memset(td->samples, 0, sizeof(int64_t) * HSK_TIMEDATA_LIMIT);
  hsk_map_init_map(&td->known, hsk_addr_hash, hsk_addr_equal, free);
  td->offset = 0;
  td->checked = false;

  return HSK_SUCCESS;
}

void
hsk_timedata_uninit(hsk_timedata_t *td) {
  if (!td)
    return;

  hsk_map_uninit(&td->known);
}

hsk_timedata_t *
hsk_timedata_alloc(void) {
  hsk_timedata_t *td = malloc(sizeof(hsk_timedata_t));
  hsk_timedata_init(td);
  return td;
}

void
hsk_timedata_free(hsk_timedata_t *td) {
  if (!td)
    return;

  hsk_timedata_uninit(td);
  free(td);
}

static void
hsk_timedata_log(hsk_timedata_t *td, const char *fmt, ...) {
  printf("timedata: ");

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

static void
hsk_timedata_insert(hsk_timedata_t *td, int64_t sample) {
  int32_t start = 0;
  int32_t end = td->sample_len - 1;
  int32_t i = -1;

  while (start <= end) {
    int32_t pos = (start + end) >> 1;
    int32_t cmp = td->samples[pos] - sample;

    if (cmp == 0) {
      i = pos;
      break;
    }

    if (cmp < 0)
      start = pos + 1;
    else
      end = pos - 1;
  }

  if (i == -1)
    i = start;

  assert(td->sample_len + 1 <= HSK_TIMEDATA_LIMIT);

  int32_t j;
  for (j = i + 1; j < td->sample_len + 1; j++)
    td->samples[j] = td->samples[j - 1];

  td->samples[i] = sample;
  td->sample_len += 1;
}

int32_t
hsk_timedata_add(hsk_timedata_t *td, hsk_addr_t *addr, int64_t time) {
  if (td->sample_len >= HSK_TIMEDATA_LIMIT)
    return HSK_SUCCESS;

  if (hsk_map_has(&td->known, addr))
    return HSK_SUCCESS;

  hsk_addr_t *id = hsk_addr_clone(addr);

  if (!id)
    return HSK_ENOMEM;

  if (!hsk_map_set(&td->known, (void *)id, (void *)id)) {
    free(id);
    return HSK_ENOMEM;
  }

  int64_t sample = time - hsk_now();

  hsk_timedata_insert(td, sample);

  if (td->sample_len >= 5 && (td->sample_len % 2) == 1) {
    int64_t median = td->samples[td->sample_len >> 1];

    if (median < 0)
      median = -median;

    if (median >= 70 * 60) {
      if (!td->checked) {
        bool match = false;
        int32_t i;

        for (i = 0; i < td->sample_len; i++) {
          int64_t offset = td->samples[i];

          if (offset < 0)
            offset = -offset;

          if (offset != 0 && offset < 5 * 60) {
            match = true;
            break;
          }
        }

        if (!match) {
          td->checked = true;
          hsk_timedata_log(td, "WARNING: timing mismatch!");
        }
      }

      median = 0;
    }

    td->offset = median;

    hsk_timedata_log(td, "added new time sample\n");
    hsk_timedata_log(td, "  new adjusted time: %d\n", hsk_timedata_now(td));
    hsk_timedata_log(td, "  offset: %d\n", td->offset);
  }

  return HSK_SUCCESS;
}

int64_t
hsk_timedata_now(hsk_timedata_t *td) {
  return hsk_now() + td->offset;
}

int64_t
hsk_timedata_adjust(hsk_timedata_t *td, int64_t time) {
  return time + td->offset;
}

int64_t
hsk_timedata_local(hsk_timedata_t *td, int64_t time) {
  return time - td->offset;
}

int64_t
hsk_timedata_ms(hsk_timedata_t *td) {
  return (hsk_now() + td->offset) * 1000;
}
