#ifndef _HSK_HASH_H
#define _HSK_HASH_H

void
hsk_blake2b(uint8_t *data, size_t data_len, uint8_t *hash);

void
hsk_sha256(uint8_t *data, size_t data_len, uint8_t *hash);

void
hsk_hash256(uint8_t *data, size_t data_len, uint8_t *hash);

#endif
