#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Taken from:
// https://github.com/wahern/dns/blob/master/src/dns.c
#ifndef _HSK_RANDOM
#if defined(HAVE_ARC4RANDOM)  \
  || defined(__OpenBSD__)     \
  || defined(__FreeBSD__)     \
  || defined(__NetBSD__)      \
  || defined(__APPLE__)
#define _HSK_RANDOM arc4random
#elif __linux
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

uint32_t
hsk_random(void) {
  return _HSK_RANDOM();
}

uint64_t
hsk_nonce(void) {
  return (((uint64_t)hsk_random()) << 32) + hsk_random();
}

static inline int32_t
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
hsk_hex_encode(uint8_t *data, size_t data_len, char *str) {
  if (data == NULL && data_len != 0)
    return false;

  if (str == NULL)
    return false;

  size_t size = data_len << 1;

  int32_t i;
  int32_t p = 0;

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

char *
hsk_hex_encode32(uint8_t *data) {
  static char str[65];
  assert(hsk_hex_encode(data, 32, str));
  return str;
}

size_t
hsk_hex_decode_size(char *str) {
  if (str == NULL)
    return 0;
  return strlen(str) >> 1;
}

bool
hsk_hex_decode(char *str, uint8_t *data) {
  if (str == NULL)
    return true;

  int32_t i;
  char *s;

  int32_t p = 0;
  uint8_t w;

  for (i = 0, s = str; *s; i++, s++) {
    int32_t n = to_nibble(*s);

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
