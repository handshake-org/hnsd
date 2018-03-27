/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HSK_SECP256K1_MODULE_ECDH_MAIN_H
#define HSK_SECP256K1_MODULE_ECDH_MAIN_H

#include "ecdh.h"
#include "ecmult_const_impl.h"

int hsk_secp256k1_ecdh(const hsk_secp256k1_context* ctx, unsigned char *result, const hsk_secp256k1_pubkey *point, const unsigned char *scalar) {
    int ret = 0;
    int overflow = 0;
    hsk_secp256k1_gej res;
    hsk_secp256k1_ge pt;
    hsk_secp256k1_scalar s;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(result != NULL);
    ARG_CHECK(point != NULL);
    ARG_CHECK(scalar != NULL);

    hsk_secp256k1_pubkey_load(ctx, &pt, point);
    hsk_secp256k1_scalar_set_b32(&s, scalar, &overflow);
    if (overflow || hsk_secp256k1_scalar_is_zero(&s)) {
        ret = 0;
    } else {
        unsigned char x[32];
        unsigned char y[1];
        hsk_secp256k1_sha256 sha;

        hsk_secp256k1_ecmult_const(&res, &pt, &s);
        hsk_secp256k1_ge_set_gej(&pt, &res);
        /* Compute a hash of the point in compressed form
         * Note we cannot use hsk_secp256k1_eckey_pubkey_serialize here since it does not
         * expect its output to be secret and has a timing sidechannel. */
        hsk_secp256k1_fe_normalize(&pt.x);
        hsk_secp256k1_fe_normalize(&pt.y);
        hsk_secp256k1_fe_get_b32(x, &pt.x);
        y[0] = 0x02 | hsk_secp256k1_fe_is_odd(&pt.y);

        hsk_secp256k1_sha256_initialize(&sha);
        hsk_secp256k1_sha256_write(&sha, y, sizeof(y));
        hsk_secp256k1_sha256_write(&sha, x, sizeof(x));
        hsk_secp256k1_sha256_finalize(&sha, result);
        ret = 1;
    }

    hsk_secp256k1_scalar_clear(&s);
    return ret;
}

#endif /* HSK_SECP256K1_MODULE_ECDH_MAIN_H */
