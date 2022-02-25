#ifndef _HSK_UTILS_H
#define _HSK_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "uv.h"

int64_t
hsk_now(void);

void
hsk_date(
  int64_t now,
  uint32_t *year,
  uint32_t *month,
  uint32_t *day,
  uint32_t *hour,
  uint32_t *min,
  uint32_t *sec
);

void
hsk_ymdh(uint32_t *year, uint32_t *month, uint32_t *day, uint32_t *hour);

void
hsk_ymd(uint32_t *year, uint32_t *month, uint32_t *day);

uint32_t
hsk_random(void);

uint64_t
hsk_nonce(void);

size_t
hsk_hex_encode_size(size_t data_len);

char *
hsk_hex_encode(const uint8_t *data, size_t data_len, char *str);

const char *
hsk_hex_encode32(const uint8_t *data);

const char *
hsk_hex_encode20(const uint8_t *data);

size_t
hsk_hex_decode_size(const char *str);

bool
hsk_hex_decode(const char *str, uint8_t *data);

void
hsk_to_lower(uint8_t *name);

// Close and then free a libuv handle (with free()).
// libuv specifically documents that the handle memory cannot be freed until the
// async close callback is invoked, so this frees the handle in that callback.
void
hsk_uv_close_free(uv_handle_t *handle);

#endif
