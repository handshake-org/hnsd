/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HSK_SECP256K1_ECKEY_H
#define HSK_SECP256K1_ECKEY_H

#include <stddef.h>

#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "ecmult_gen.h"

static int hsk_secp256k1_eckey_pubkey_parse(hsk_secp256k1_ge *elem, const unsigned char *pub, size_t size);
static int hsk_secp256k1_eckey_pubkey_serialize(hsk_secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed);

static int hsk_secp256k1_eckey_privkey_tweak_add(hsk_secp256k1_scalar *key, const hsk_secp256k1_scalar *tweak);
static int hsk_secp256k1_eckey_pubkey_tweak_add(const hsk_secp256k1_ecmult_context *ctx, hsk_secp256k1_ge *key, const hsk_secp256k1_scalar *tweak);
static int hsk_secp256k1_eckey_privkey_tweak_mul(hsk_secp256k1_scalar *key, const hsk_secp256k1_scalar *tweak);
static int hsk_secp256k1_eckey_pubkey_tweak_mul(const hsk_secp256k1_ecmult_context *ctx, hsk_secp256k1_ge *key, const hsk_secp256k1_scalar *tweak);

#endif /* HSK_SECP256K1_ECKEY_H */
