#ifndef _HSK_UTILS_H
#define _HSK_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

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
hsk_hex_encode(uint8_t *data, size_t data_len, char *str);

char *
hsk_hex_encode32(uint8_t *data);

size_t
hsk_hex_decode_size(char *str);

bool
hsk_hex_decode(char *str, uint8_t *data);

void
hsk_to_lower(char *name);
#endif
