/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HSK_SECP256K1_HASH_H
#define HSK_SECP256K1_HASH_H

#include <stdlib.h>
#include <stdint.h>

typedef struct {
    uint32_t s[8];
    uint32_t buf[16]; /* In big endian */
    size_t bytes;
} hsk_secp256k1_sha256;

static void hsk_secp256k1_sha256_initialize(hsk_secp256k1_sha256 *hash);
static void hsk_secp256k1_sha256_write(hsk_secp256k1_sha256 *hash, const unsigned char *data, size_t size);
static void hsk_secp256k1_sha256_finalize(hsk_secp256k1_sha256 *hash, unsigned char *out32);

typedef struct {
    hsk_secp256k1_sha256 inner, outer;
} hsk_secp256k1_hmac_sha256;

static void hsk_secp256k1_hmac_sha256_initialize(hsk_secp256k1_hmac_sha256 *hash, const unsigned char *key, size_t size);
static void hsk_secp256k1_hmac_sha256_write(hsk_secp256k1_hmac_sha256 *hash, const unsigned char *data, size_t size);
static void hsk_secp256k1_hmac_sha256_finalize(hsk_secp256k1_hmac_sha256 *hash, unsigned char *out32);

typedef struct {
    unsigned char v[32];
    unsigned char k[32];
    int retry;
} hsk_secp256k1_rfc6979_hmac_sha256;

static void hsk_secp256k1_rfc6979_hmac_sha256_initialize(hsk_secp256k1_rfc6979_hmac_sha256 *rng, const unsigned char *key, size_t keylen);
static void hsk_secp256k1_rfc6979_hmac_sha256_generate(hsk_secp256k1_rfc6979_hmac_sha256 *rng, unsigned char *out, size_t outlen);
static void hsk_secp256k1_rfc6979_hmac_sha256_finalize(hsk_secp256k1_rfc6979_hmac_sha256 *rng);

#endif /* HSK_SECP256K1_HASH_H */
