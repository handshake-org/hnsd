#ifndef _HSK_BASE32_H
#define _HSK_BASE32_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

int32_t
hsk_base32_encode(uint8_t *data, size_t data_len, char *out, bool pad);

int32_t
hsk_base32_encode_hex(uint8_t *data, size_t data_len, char *out, bool pad);

int32_t
hsk_base32_encode_size(uint8_t *data, size_t data_len, bool pad);

int32_t
hsk_base32_encode_hex_size(uint8_t *data, size_t data_len, bool pad);

int32_t
hsk_base32_decode(char *str, uint8_t *out, bool unpad);

int32_t
hsk_base32_decode_hex(char *str, uint8_t *out, bool unpad);

int32_t
hsk_base32_decode_size(char *str);

int32_t
hsk_base32_decode_hex_size(char *str);

bool
hsk_base32_test(char *str, bool unpad);

bool
hsk_base32_test_hex(char *str, bool unpad);
#endif
