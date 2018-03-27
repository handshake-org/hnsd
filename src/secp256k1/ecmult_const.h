/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HSK_SECP256K1_ECMULT_CONST_H
#define HSK_SECP256K1_ECMULT_CONST_H

#include "scalar.h"
#include "group.h"

static void hsk_secp256k1_ecmult_const(hsk_secp256k1_gej *r, const hsk_secp256k1_ge *a, const hsk_secp256k1_scalar *q);

#endif /* HSK_SECP256K1_ECMULT_CONST_H */
