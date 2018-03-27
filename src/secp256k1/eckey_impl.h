/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HSK_SECP256K1_ECKEY_IMPL_H
#define HSK_SECP256K1_ECKEY_IMPL_H

#include "eckey.h"

#include "scalar.h"
#include "field.h"
#include "group.h"
#include "ecmult_gen.h"

static int hsk_secp256k1_eckey_pubkey_parse(hsk_secp256k1_ge *elem, const unsigned char *pub, size_t size) {
    if (size == 33 && (pub[0] == HSK_SECP256K1_TAG_PUBKEY_EVEN || pub[0] == HSK_SECP256K1_TAG_PUBKEY_ODD)) {
        hsk_secp256k1_fe x;
        return hsk_secp256k1_fe_set_b32(&x, pub+1) && hsk_secp256k1_ge_set_xo_var(elem, &x, pub[0] == HSK_SECP256K1_TAG_PUBKEY_ODD);
    } else if (size == 65 && (pub[0] == 0x04 || pub[0] == 0x06 || pub[0] == 0x07)) {
        hsk_secp256k1_fe x, y;
        if (!hsk_secp256k1_fe_set_b32(&x, pub+1) || !hsk_secp256k1_fe_set_b32(&y, pub+33)) {
            return 0;
        }
        hsk_secp256k1_ge_set_xy(elem, &x, &y);
        if ((pub[0] == HSK_SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == HSK_SECP256K1_TAG_PUBKEY_HYBRID_ODD) &&
            hsk_secp256k1_fe_is_odd(&y) != (pub[0] == HSK_SECP256K1_TAG_PUBKEY_HYBRID_ODD)) {
            return 0;
        }
        return hsk_secp256k1_ge_is_valid_var(elem);
    } else {
        return 0;
    }
}

static int hsk_secp256k1_eckey_pubkey_serialize(hsk_secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed) {
    if (hsk_secp256k1_ge_is_infinity(elem)) {
        return 0;
    }
    hsk_secp256k1_fe_normalize_var(&elem->x);
    hsk_secp256k1_fe_normalize_var(&elem->y);
    hsk_secp256k1_fe_get_b32(&pub[1], &elem->x);
    if (compressed) {
        *size = 33;
        pub[0] = hsk_secp256k1_fe_is_odd(&elem->y) ? HSK_SECP256K1_TAG_PUBKEY_ODD : HSK_SECP256K1_TAG_PUBKEY_EVEN;
    } else {
        *size = 65;
        pub[0] = HSK_SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
        hsk_secp256k1_fe_get_b32(&pub[33], &elem->y);
    }
    return 1;
}

static int hsk_secp256k1_eckey_privkey_tweak_add(hsk_secp256k1_scalar *key, const hsk_secp256k1_scalar *tweak) {
    hsk_secp256k1_scalar_add(key, key, tweak);
    if (hsk_secp256k1_scalar_is_zero(key)) {
        return 0;
    }
    return 1;
}

static int hsk_secp256k1_eckey_pubkey_tweak_add(const hsk_secp256k1_ecmult_context *ctx, hsk_secp256k1_ge *key, const hsk_secp256k1_scalar *tweak) {
    hsk_secp256k1_gej pt;
    hsk_secp256k1_scalar one;
    hsk_secp256k1_gej_set_ge(&pt, key);
    hsk_secp256k1_scalar_set_int(&one, 1);
    hsk_secp256k1_ecmult(ctx, &pt, &pt, &one, tweak);

    if (hsk_secp256k1_gej_is_infinity(&pt)) {
        return 0;
    }
    hsk_secp256k1_ge_set_gej(key, &pt);
    return 1;
}

static int hsk_secp256k1_eckey_privkey_tweak_mul(hsk_secp256k1_scalar *key, const hsk_secp256k1_scalar *tweak) {
    if (hsk_secp256k1_scalar_is_zero(tweak)) {
        return 0;
    }

    hsk_secp256k1_scalar_mul(key, key, tweak);
    return 1;
}

static int hsk_secp256k1_eckey_pubkey_tweak_mul(const hsk_secp256k1_ecmult_context *ctx, hsk_secp256k1_ge *key, const hsk_secp256k1_scalar *tweak) {
    hsk_secp256k1_scalar zero;
    hsk_secp256k1_gej pt;
    if (hsk_secp256k1_scalar_is_zero(tweak)) {
        return 0;
    }

    hsk_secp256k1_scalar_set_int(&zero, 0);
    hsk_secp256k1_gej_set_ge(&pt, key);
    hsk_secp256k1_ecmult(ctx, &pt, &pt, tweak, &zero);
    hsk_secp256k1_ge_set_gej(key, &pt);
    return 1;
}

#endif /* HSK_SECP256K1_ECKEY_IMPL_H */
