#ifndef _HSK_HASH_H
#define _HSK_HASH_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

int32_t
hsk_hash_blake2b(uint8_t *data, size_t data_len, uint8_t *hash);

void
hsk_hash_sha256(uint8_t *data, size_t data_len, uint8_t *hash);

void
hsk_hash_hash256(uint8_t *data, size_t data_len, uint8_t *hash);
#endif
