/*
 * https://github.com/littlstar/b64.c
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Little Star Media, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>

#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>

#include "b64.h"

static const char b64_table[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'
};

bool
b64_decode(const char *src, size_t len, uint8_t **out, size_t *out_len) {
  int32_t i = 0;
  int32_t j = 0;
  int32_t l = 0;
  size_t size = 0;
  uint8_t *dec = NULL;
  uint8_t buf[3];
  uint8_t tmp[4];

  // alloc
  dec = (uint8_t *)malloc(1);
  if (dec == NULL)
    return false;

  // parse until end of source
  while (len--) {
    // break if char is `=' or not base64 char
    if (src[j] == '=')
      break;

    if (!(isalnum(src[j]) || src[j] == '+' || src[j] == '/'))
      break;

    // read up to 4 bytes at a time into `tmp'
    tmp[i++] = src[j++];

    // if 4 bytes read then decode into `buf'
    if (i == 4) {
      // translate values in `tmp' from table
      for (i = 0; i < 4; i++) {
        // find translation char in `b64_table'
        for (l = 0; l < 64; l++) {
          if (tmp[i] == b64_table[l]) {
            tmp[i] = l;
            break;
          }
        }
      }

      // decode
      buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
      buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
      buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];

      // write decoded buffer to `dec'
      dec = (uint8_t *)realloc(dec, size + 3);

      if (dec == NULL)
        return false;

      for (i = 0; i < 3; i++)
        dec[size++] = buf[i];

      // reset
      i = 0;
    }
  }

  // remainder
  if (i > 0) {
    // fill `tmp' with `\0' at most 4 times
    for (j = i; j < 4; j++)
      tmp[j] = '\0';

    // translate remainder
    for (j = 0; j < 4; j++) {
        // find translation char in `b64_table'
        for (l = 0; l < 64; ++l) {
          if (tmp[j] == b64_table[l]) {
            tmp[j] = l;
            break;
          }
        }
    }

    // decode remainder
    buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
    buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
    buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];

    // write remainer decoded buffer to `dec'
    dec = (uint8_t *)realloc(dec, size + (i - 1));

    if (dec == NULL)
      return false;

    for (j = 0; (j < i - 1); j++)
      dec[size++] = buf[j];
  }

  // Make sure we have enough space to add '\0' character at end.
  dec = (uint8_t *)realloc(dec, size + 1);
  if (dec == NULL)
    return false;

  dec[size] = '\0';

  // Return back the size of decoded string if demanded.
  *out = dec;
  *out_len = size;

  return true;
}
