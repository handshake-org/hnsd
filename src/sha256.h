/* sha.h sha256 hash function */
#ifndef HSK_SHA_256_H
#define HSK_SHA_256_H
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define hsk_sha256_block_size 64
#define hsk_sha256_hash_size  32

/* algorithm context */
typedef struct hsk_sha256_ctx
{
	unsigned message[16];   /* 512-bit buffer for leftovers */
	uint64_t length;        /* number of processed bytes */
	unsigned hash[8];       /* 256-bit algorithm internal hashing state */
	unsigned digest_length; /* length of the algorithm digest in bytes */
} hsk_sha256_ctx;

void hsk_sha256_init(hsk_sha256_ctx *ctx);
void hsk_sha256_update(hsk_sha256_ctx *ctx, const unsigned char* data, size_t length);
void hsk_sha256_final(hsk_sha256_ctx *ctx, unsigned char result[32]);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* HSK_SHA_256_H */
