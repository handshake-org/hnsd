#ifndef _HSK_BASE32_H
#define _HSK_BASE32_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

int32_t
hsk_base32_encode(const uint8_t *data, size_t data_len, char *out, bool pad);

int32_t
hsk_base32_encode_hex(
  const uint8_t *data,
  size_t data_len,
  char *out,
  bool pad
);

int32_t
hsk_base32_encode_size(const uint8_t *data, size_t data_len, bool pad);

int32_t
hsk_base32_encode_hex_size(const uint8_t *data, size_t data_len, bool pad);

int32_t
hsk_base32_decode(const char *str, uint8_t *out, bool unpad);

int32_t
hsk_base32_decode_hex(const char *str, uint8_t *out, bool unpad);

int32_t
hsk_base32_decode_size(const char *str);

int32_t
hsk_base32_decode_hex_size(const char *str);

bool
hsk_base32_test(const char *str, bool unpad);

bool
hsk_base32_test_hex(const char *str, bool unpad);
#endif
