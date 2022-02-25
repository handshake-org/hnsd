#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "uv.h"

// Taken from:
// https://github.com/wahern/dns/blob/master/src/dns.c
#ifndef _HSK_RANDOM
#if defined(HAVE_ARC4RANDOM)  \
  || defined(__OpenBSD__)     \
  || defined(__FreeBSD__)     \
  || defined(__NetBSD__)      \
  || defined(__APPLE__)
#define _HSK_RANDOM arc4random
#elif defined(__linux)
#define _HSK_RANDOM random
#else
#define _HSK_RANDOM rand
#endif
#endif

int64_t
hsk_now(void) {
  time_t n = time(NULL);
  assert(n >= 0);
  return (int64_t)n;
}

void
hsk_date(
  int64_t now,
  uint32_t *year,
  uint32_t *month,
  uint32_t *day,
  uint32_t *hour,
  uint32_t *min,
  uint32_t *sec
) {
  // https://stackoverflow.com/questions/7136385
  int s = (int)now;
  int z = s / 86400 + 719468;
  int era = (z >= 0 ? z : z - 146096) / 146097;
  unsigned int doe = (unsigned int)(z - era * 146097);
  unsigned int yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  int y = (int)yoe + era * 400;
  unsigned int doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  unsigned int mp = (5 * doy + 2) / 153;
  unsigned int d = doy - (153 * mp + 2) / 5 + 1;
  unsigned int m = mp + (mp < 10 ? 3 : -9);

  y += (m <= 2);

  if (year)
    *year = y;

  if (month)
    *month = m;

  if (day)
    *day = d;

  if (hour)
    *hour = (s / 3600) % 24;

  if (min)
    *min = (s / 60) % 60;

  if (sec)
    *sec = s % 60;
}

void
hsk_ymdh(uint32_t *year, uint32_t *month, uint32_t *day, uint32_t *hour) {
  hsk_date(hsk_now(), year, month, day, hour, NULL, NULL);
}

void
hsk_ymd(uint32_t *year, uint32_t *month, uint32_t *day) {
  hsk_date(hsk_now(), year, month, day, NULL, NULL, NULL);
}

uint32_t
hsk_random(void) {
  return _HSK_RANDOM();
}

uint64_t
hsk_nonce(void) {
  return (((uint64_t)hsk_random()) << 32) + hsk_random();
}

static inline int
to_nibble(char s) {
  if (s >= '0' && s <= '9')
    return s - '0';

  if (s >= 'A' && s <= 'F')
    return (s - 'A') + 0x0a;

  if (s >= 'a' && s <= 'f')
    return (s - 'a') + 0x0a;

  return -1;
}

static inline char
to_char(uint8_t n) {
  if (n >= 0x00 && n <= 0x09)
    return n + '0';

  if (n >= 0x0a && n <= 0x0f)
    return (n - 0x0a) + 'a';

  return -1;
}

size_t
hsk_hex_encode_size(size_t data_len) {
  return (data_len << 1) + 1;
}

bool
hsk_hex_encode(const uint8_t *data, size_t data_len, char *str) {
  if (data == NULL && data_len != 0)
    return false;

  if (str == NULL)
    return false;

  size_t size = data_len << 1;

  int i;
  int p = 0;

  for (i = 0; i < size; i++) {
    char ch;

    if (i & 1) {
      ch = to_char(data[p] & 15);
      p += 1;
    } else {
      ch = to_char(data[p] >> 4);
    }

    if (ch == -1)
      return false;

    str[i] = ch;
  }

  str[i] = '\0';

  return true;
}

const char *
hsk_hex_encode32(const uint8_t *data) {
  static char str[65];
  assert(hsk_hex_encode(data, 32, str));
  return str;
}

const char *
hsk_hex_encode20(const uint8_t *data) {
  static char str[41];
  assert(hsk_hex_encode(data, 20, str));
  return str;
}

size_t
hsk_hex_decode_size(const char *str) {
  if (str == NULL)
    return 0;
  return strlen(str) >> 1;
}

bool
hsk_hex_decode(const char *str, uint8_t *data) {
  if (str == NULL)
    return true;

  int i;
  char *s;

  int p = 0;
  uint8_t w = 0;

  for (i = 0, s = (char *)str; *s; i++, s++) {
    int n = to_nibble(*s);

    if (n == -1)
      return false;

    if (i & 1) {
      w |= (uint8_t)n;
      if (data)
        data[p] = w;
      p += 1;
    } else {
      w = ((uint8_t)n) << 4;
    }
  }

  if (i & 1)
    return false;

  return true;
}

void
hsk_to_lower(uint8_t *name) {
  assert(name);

  uint8_t off = 0;

  for (;;) {
    uint8_t label = name[off++];

    if (label == 0x00)
      return;

    for (; label > 0; label--) {
      if (name[off] >= 'A' && name[off] <= 'Z')
        name[off] += ' ';

      off++;
    }
  }
}

static void
after_close_free(uv_handle_t *handle) {
  free(handle);
}

void
hsk_uv_close_free(uv_handle_t *handle) {
  if (handle)
    uv_close(handle, after_close_free);
}
