#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <stdint.h>
#include <stdbool.h>

#include "hsk-base32.h"

static const char CHARSET[] = "abcdefghijklmnopqrstuvwxyz234567";

static const int8_t TABLE[] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1
};

static const char CHARSET_HEX[] = "0123456789abcdefghijklmnopqrstuv";

static const int8_t TABLE_HEX[] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
  25, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
  25, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

static const uint8_t PADDING[] = { 0, 6, 4, 3, 1 };

int32_t
hsk_base32_encode(uint8_t *data, size_t data_len, char *out, bool pad) {
  return hsk_base32_encode2(CHARSET, data, data_len, out, pad);
}

int32_t
hsk_base32_encode_hex(uint8_t *data, size_t data_len, char *out, bool pad) {
  return hsk_base32_encode2(CHARSET_HEX, data, data_len, out, pad);
}

int32_t
hsk_base32_encode_size(uint8_t *data, size_t data_len, bool pad) {
  return hsk_base32_encode2(CHARSET, data, data_len, NULL, pad);
}

int32_t
hsk_base32_encode_hex_size(uint8_t *data, size_t data_len, bool pad) {
  return hsk_base32_encode2(CHARSET_HEX, data, data_len, NULL, pad);
}

int32_t
hsk_base32_encode2(
  char *charset,
  uint8_t *data,
  size_t data_len,
  char *out,
  bool pad
) {
  assert(charset);

  int32_t off = 0;
  int32_t mode = 0;
  int32_t left = 0;
  int32_t i;

  for (i = 0; i < data_len; i++) {
    uint8_t ch = data[i];

    switch (mode) {
      case 0:
        if (out)
          out[off] = charset[ch >> 3];
        off += 1;
        left = (ch & 7) << 2;
        mode = 1;
        break;
      case 1:
        if (out) {
          out[off] = charset[left | (ch >> 6)];
          out[off + 1] = charset[(ch >> 1) & 31];
        }
        off += 2;
        left = (ch & 1) << 4;
        mode = 2;
        break;
      case 2:
        if (out)
          out[off] = charset[left | (ch >> 4)];
        off += 1;
        left = (ch & 15) << 1;
        mode = 3;
        break;
      case 3:
        if (out) {
          out[off] = charset[left | (ch >> 7)];
          out[off + 1] = charset[(ch >> 2) & 31];
        }
        off += 2;
        left = (ch & 3) << 3;
        mode = 4;
        break;
      case 4:
        if (out) {
          out[off] = charset[left | (ch >> 5)];
          out[off + 1] = charset[ch & 31];
        }
        off += 2;
        mode = 0;
        break;
    }
  }

  if (mode > 0) {
    if (out)
      out[off] = charset[left];

    off += 1;

    if (pad) {
      for (i = 0; i < PADDING[mode]; i++) {
        if (out)
          out[off] = '=';
        off += 1;
      }
    }
  }

  if (out)
    out[off] = '\0';

  off += 1;

  return off;
}

int32_t
hsk_base32_decode(char *str, uint8_t *out, bool unpad) {
  return hsk_base32_decode2(TABLE, str, out, unpad);
}

int32_t
hsk_base32_decode_hex(char *str, uint8_t *out, bool unpad) {
  return hsk_base32_decode2(TABLE_HEX, str, out, unpad);
}

int32_t
hsk_base32_decode_size(char *str) {
  int32_t size hsk_base32_decode2(TABLE, str, NULL, false);

  if (size == -1)
    return strlen(str) * 5 / 8;

  return size;
}

int32_t
hsk_base32_decode_hex_size(char *str, uint8_t *out) {
  int32_t size = hsk_base32_decode2(TABLE_HEX, str, NULL, false);

  if (size == -1)
    return strlen(str) * 5 / 8;

  return size;
}

int32_t
hsk_base32_decode2(uint8_t *table, char *str, uint8_t *out, bool unpad) {
  assert(table);
  assert(str);

  int32_t mode = 0;
  int32_t left = 0;
  int32_t j = 0;
  int32_t i = 0;
  size_t len = strlen(str);

  for (; i < len; i++) {
    char ch = str[i];
    char v = (ch & 0x80) ? -1 : table[ch];

    if (v == -1) {
      if (unpad && mode > 0)
        break;
      return -1;
    }

    switch (mode) {
      case 0:
        left = v;
        mode = 1;
        break;
      case 1:
        if (data)
          data[j] = (left << 3) | (v >> 2);
        j += 1;
        left = v & 3;
        mode = 2;
        break;
      case 2:
        left = left << 5 | v;
        mode = 3;
        break;
      case 3:
        if (data)
          data[j] = (left << 1) | (v >> 4);
        j += 1;
        left = v & 15;
        mode = 4;
        break;
      case 4:
        if (data)
          data[j] = (left << 4) | (v >> 1);
        j += 1;
        left = v & 1;
        mode = 5;
        break;
      case 5:
        left = left << 5 | v;
        mode = 6;
        break;
      case 6:
        if (data)
          data[j] = (left << 2) | (v >> 3);
        j += 1;
        left = v & 7;
        mode = 7;
        break;
      case 7:
        if (data)
          data[j] = (left << 5) | v;
        j += 1;
        mode = 0;
        break;
    }
  }

  if (unpad) {
    switch (mode) {
      case 0:
        break;
      case 1:
      case 3:
      case 6:
        return -1;
      case 2:
        if (left > 0)
          return -1;

        if (len != i + 6)
          return -1;

        if (strncmp(str + i, "======", 6) != 0)
          return -1;

        break;
      case 4:
        if (left > 0)
          return -1;

        if (len != i + 4)
          return -1;

        if (strncmp(str + i, "====", 4) != 0)
          return -1;

        break;
      case 5:
        if (left > 0)
          return -1;

        if (len != i + 3)
          return -1;

        if (strncmp(str + i, "===", 3) != 0)
          return -1;

        break;
      case 7:
        if (left > 0)
          return -1;

        if (len != i + 1)
          return -1;

        if (str[i] != '=')
          return -1;

        break;
    }
  }

  return j;
};

bool
hsk_base32_test(char *str, uint8_t *out, bool unpad) {
  return hsk_base32_decode(str, NULL, unpad) != -1;
}

bool
hsk_base32_decode_hex(char *str, bool unpad) {
  return hsk_base32_decode(str, NULL, unpad) != -1;
}
