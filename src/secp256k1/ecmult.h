/**********************************************************************
 * Copyright (c) 2013, 2014, 2017 Pieter Wuille, Andrew Poelstra      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HSK_SECP256K1_ECMULT_H
#define HSK_SECP256K1_ECMULT_H

#include "num.h"
#include "group.h"
#include "scalar.h"
#include "scratch.h"

typedef struct {
    /* For accelerating the computation of a*P + b*G: */
    hsk_secp256k1_ge_storage (*pre_g)[];    /* odd multiples of the generator */
#ifdef HSK_USE_ENDOMORPHISM
    hsk_secp256k1_ge_storage (*pre_g_128)[]; /* odd multiples of 2^128*generator */
#endif
} hsk_secp256k1_ecmult_context;

static void hsk_secp256k1_ecmult_context_init(hsk_secp256k1_ecmult_context *ctx);
static void hsk_secp256k1_ecmult_context_build(hsk_secp256k1_ecmult_context *ctx, const hsk_secp256k1_callback *cb);
static void hsk_secp256k1_ecmult_context_clone(hsk_secp256k1_ecmult_context *dst,
                                           const hsk_secp256k1_ecmult_context *src, const hsk_secp256k1_callback *cb);
static void hsk_secp256k1_ecmult_context_clear(hsk_secp256k1_ecmult_context *ctx);
static int hsk_secp256k1_ecmult_context_is_built(const hsk_secp256k1_ecmult_context *ctx);

/** Double multiply: R = na*A + ng*G */
static void hsk_secp256k1_ecmult(const hsk_secp256k1_ecmult_context *ctx, hsk_secp256k1_gej *r, const hsk_secp256k1_gej *a, const hsk_secp256k1_scalar *na, const hsk_secp256k1_scalar *ng);

typedef int (hsk_secp256k1_ecmult_multi_callback)(hsk_secp256k1_scalar *sc, hsk_secp256k1_ge *pt, size_t idx, void *data);

/**
 * Multi-multiply: R = inp_g_sc * G + sum_i ni * Ai.
 * Chooses the right algorithm for a given number of points and scratch space
 * size. Resets and overwrites the given scratch space. If the points do not
 * fit in the scratch space the algorithm is repeatedly run with batches of
 * points.
 * Returns: 1 on success (including when inp_g_sc is NULL and n is 0)
 *          0 if there is not enough scratch space for a single point or
 *          callback returns 0
 */
static int hsk_secp256k1_ecmult_multi_var(const hsk_secp256k1_ecmult_context *ctx, hsk_secp256k1_scratch *scratch, hsk_secp256k1_gej *r, const hsk_secp256k1_scalar *inp_g_sc, hsk_secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n);

#endif /* HSK_SECP256K1_ECMULT_H */
