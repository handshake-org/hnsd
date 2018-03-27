/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HSK_SECP256K1_ECDSA_H
#define HSK_SECP256K1_ECDSA_H

#include <stddef.h>

#include "scalar.h"
#include "group.h"
#include "ecmult.h"

static int hsk_secp256k1_ecdsa_sig_parse(hsk_secp256k1_scalar *r, hsk_secp256k1_scalar *s, const unsigned char *sig, size_t size);
static int hsk_secp256k1_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const hsk_secp256k1_scalar *r, const hsk_secp256k1_scalar *s);
static int hsk_secp256k1_ecdsa_sig_verify(const hsk_secp256k1_ecmult_context *ctx, const hsk_secp256k1_scalar* r, const hsk_secp256k1_scalar* s, const hsk_secp256k1_ge *pubkey, const hsk_secp256k1_scalar *message);
static int hsk_secp256k1_ecdsa_sig_sign(const hsk_secp256k1_ecmult_gen_context *ctx, hsk_secp256k1_scalar* r, hsk_secp256k1_scalar* s, const hsk_secp256k1_scalar *seckey, const hsk_secp256k1_scalar *message, const hsk_secp256k1_scalar *nonce, int *recid);

#endif /* HSK_SECP256K1_ECDSA_H */
