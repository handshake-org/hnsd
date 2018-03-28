#ifndef _HSK_UTILS_H
#define _HSK_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

int64_t
hsk_now(void);

uint32_t
hsk_random(void);

uint64_t
hsk_nonce(void);

size_t
hsk_hex_encode_size(size_t);

char *
hsk_hex_encode(uint8_t *, size_t, char *);

char *
hsk_hex_encode32(uint8_t *);

size_t
hsk_hex_decode_size(char *);

bool
hsk_hex_decode(char *, uint8_t *);
#endif
