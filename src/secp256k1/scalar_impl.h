/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HSK_SECP256K1_SCALAR_IMPL_H
#define HSK_SECP256K1_SCALAR_IMPL_H

#include "group.h"
#include "scalar.h"

#if defined HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(EXHAUSTIVE_TEST_ORDER)
#include "scalar_low_impl.h"
#elif defined(HSK_USE_SCALAR_4X64)
#include "scalar_4x64_impl.h"
#elif defined(HSK_USE_SCALAR_8X32)
#include "scalar_8x32_impl.h"
#else
#error "Please select scalar implementation"
#endif

static void hsk_secp256k1_scalar_inverse(hsk_secp256k1_scalar *r, const hsk_secp256k1_scalar *x) {
#if defined(EXHAUSTIVE_TEST_ORDER)
    int i;
    *r = 0;
    for (i = 0; i < EXHAUSTIVE_TEST_ORDER; i++)
        if ((i * *x) % EXHAUSTIVE_TEST_ORDER == 1)
            *r = i;
    /* If this VERIFY_CHECK triggers we were given a noninvertible scalar (and thus
     * have a composite group order; fix it in exhaustive_tests.c). */
    VERIFY_CHECK(*r != 0);
}
#else
    hsk_secp256k1_scalar *t;
    int i;
    /* First compute xN as x ^ (2^N - 1) for some values of N,
     * and uM as x ^ M for some values of M. */
    hsk_secp256k1_scalar x2, x3, x6, x8, x14, x28, x56, x112, x126;
    hsk_secp256k1_scalar u2, u5, u9, u11, u13;

    hsk_secp256k1_scalar_sqr(&u2, x);
    hsk_secp256k1_scalar_mul(&x2, &u2,  x);
    hsk_secp256k1_scalar_mul(&u5, &u2, &x2);
    hsk_secp256k1_scalar_mul(&x3, &u5,  &u2);
    hsk_secp256k1_scalar_mul(&u9, &x3, &u2);
    hsk_secp256k1_scalar_mul(&u11, &u9, &u2);
    hsk_secp256k1_scalar_mul(&u13, &u11, &u2);

    hsk_secp256k1_scalar_sqr(&x6, &u13);
    hsk_secp256k1_scalar_sqr(&x6, &x6);
    hsk_secp256k1_scalar_mul(&x6, &x6, &u11);

    hsk_secp256k1_scalar_sqr(&x8, &x6);
    hsk_secp256k1_scalar_sqr(&x8, &x8);
    hsk_secp256k1_scalar_mul(&x8, &x8,  &x2);

    hsk_secp256k1_scalar_sqr(&x14, &x8);
    for (i = 0; i < 5; i++) {
        hsk_secp256k1_scalar_sqr(&x14, &x14);
    }
    hsk_secp256k1_scalar_mul(&x14, &x14, &x6);

    hsk_secp256k1_scalar_sqr(&x28, &x14);
    for (i = 0; i < 13; i++) {
        hsk_secp256k1_scalar_sqr(&x28, &x28);
    }
    hsk_secp256k1_scalar_mul(&x28, &x28, &x14);

    hsk_secp256k1_scalar_sqr(&x56, &x28);
    for (i = 0; i < 27; i++) {
        hsk_secp256k1_scalar_sqr(&x56, &x56);
    }
    hsk_secp256k1_scalar_mul(&x56, &x56, &x28);

    hsk_secp256k1_scalar_sqr(&x112, &x56);
    for (i = 0; i < 55; i++) {
        hsk_secp256k1_scalar_sqr(&x112, &x112);
    }
    hsk_secp256k1_scalar_mul(&x112, &x112, &x56);

    hsk_secp256k1_scalar_sqr(&x126, &x112);
    for (i = 0; i < 13; i++) {
        hsk_secp256k1_scalar_sqr(&x126, &x126);
    }
    hsk_secp256k1_scalar_mul(&x126, &x126, &x14);

    /* Then accumulate the final result (t starts at x126). */
    t = &x126;
    for (i = 0; i < 3; i++) {
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &u5); /* 101 */
    for (i = 0; i < 4; i++) { /* 0 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 4; i++) { /* 0 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &u5); /* 101 */
    for (i = 0; i < 5; i++) { /* 0 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &u11); /* 1011 */
    for (i = 0; i < 4; i++) {
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &u11); /* 1011 */
    for (i = 0; i < 4; i++) { /* 0 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 5; i++) { /* 00 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 6; i++) { /* 00 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &u13); /* 1101 */
    for (i = 0; i < 4; i++) { /* 0 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &u5); /* 101 */
    for (i = 0; i < 3; i++) {
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 5; i++) { /* 0 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &u9); /* 1001 */
    for (i = 0; i < 6; i++) { /* 000 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &u5); /* 101 */
    for (i = 0; i < 10; i++) { /* 0000000 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 4; i++) { /* 0 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 9; i++) { /* 0 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &x8); /* 11111111 */
    for (i = 0; i < 5; i++) { /* 0 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &u9); /* 1001 */
    for (i = 0; i < 6; i++) { /* 00 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &u11); /* 1011 */
    for (i = 0; i < 4; i++) {
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &u13); /* 1101 */
    for (i = 0; i < 5; i++) {
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &x2); /* 11 */
    for (i = 0; i < 6; i++) { /* 00 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &u13); /* 1101 */
    for (i = 0; i < 10; i++) { /* 000000 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &u13); /* 1101 */
    for (i = 0; i < 4; i++) {
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, &u9); /* 1001 */
    for (i = 0; i < 6; i++) { /* 00000 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(t, t, x); /* 1 */
    for (i = 0; i < 8; i++) { /* 00 */
        hsk_secp256k1_scalar_sqr(t, t);
    }
    hsk_secp256k1_scalar_mul(r, t, &x6); /* 111111 */
}

HSK_SECP256K1_INLINE static int hsk_secp256k1_scalar_is_even(const hsk_secp256k1_scalar *a) {
    return !(a->d[0] & 1);
}
#endif

static void hsk_secp256k1_scalar_inverse_var(hsk_secp256k1_scalar *r, const hsk_secp256k1_scalar *x) {
  hsk_secp256k1_scalar_inverse(r, x);
}

#ifdef HSK_USE_ENDOMORPHISM
#if defined(EXHAUSTIVE_TEST_ORDER)
/**
 * Find k1 and k2 given k, such that k1 + k2 * lambda == k mod n; unlike in the
 * full case we don't bother making k1 and k2 be small, we just want them to be
 * nontrivial to get full test coverage for the exhaustive tests. We therefore
 * (arbitrarily) set k2 = k + 5 and k1 = k - k2 * lambda.
 */
static void hsk_secp256k1_scalar_split_lambda(hsk_secp256k1_scalar *r1, hsk_secp256k1_scalar *r2, const hsk_secp256k1_scalar *a) {
    *r2 = (*a + 5) % EXHAUSTIVE_TEST_ORDER;
    *r1 = (*a + (EXHAUSTIVE_TEST_ORDER - *r2) * EXHAUSTIVE_TEST_LAMBDA) % EXHAUSTIVE_TEST_ORDER;
}
#else
/**
 * The Secp256k1 curve has an endomorphism, where lambda * (x, y) = (beta * x, y), where
 * lambda is {0x53,0x63,0xad,0x4c,0xc0,0x5c,0x30,0xe0,0xa5,0x26,0x1c,0x02,0x88,0x12,0x64,0x5a,
 *            0x12,0x2e,0x22,0xea,0x20,0x81,0x66,0x78,0xdf,0x02,0x96,0x7c,0x1b,0x23,0xbd,0x72}
 *
 * "Guide to Elliptic Curve Cryptography" (Hankerson, Menezes, Vanstone) gives an algorithm
 * (algorithm 3.74) to find k1 and k2 given k, such that k1 + k2 * lambda == k mod n, and k1
 * and k2 have a small size.
 * It relies on constants a1, b1, a2, b2. These constants for the value of lambda above are:
 *
 * - a1 =      {0x30,0x86,0xd2,0x21,0xa7,0xd4,0x6b,0xcd,0xe8,0x6c,0x90,0xe4,0x92,0x84,0xeb,0x15}
 * - b1 =     -{0xe4,0x43,0x7e,0xd6,0x01,0x0e,0x88,0x28,0x6f,0x54,0x7f,0xa9,0x0a,0xbf,0xe4,0xc3}
 * - a2 = {0x01,0x14,0xca,0x50,0xf7,0xa8,0xe2,0xf3,0xf6,0x57,0xc1,0x10,0x8d,0x9d,0x44,0xcf,0xd8}
 * - b2 =      {0x30,0x86,0xd2,0x21,0xa7,0xd4,0x6b,0xcd,0xe8,0x6c,0x90,0xe4,0x92,0x84,0xeb,0x15}
 *
 * The algorithm then computes c1 = round(b1 * k / n) and c2 = round(b2 * k / n), and gives
 * k1 = k - (c1*a1 + c2*a2) and k2 = -(c1*b1 + c2*b2). Instead, we use modular arithmetic, and
 * compute k1 as k - k2 * lambda, avoiding the need for constants a1 and a2.
 *
 * g1, g2 are precomputed constants used to replace division with a rounded multiplication
 * when decomposing the scalar for an endomorphism-based point multiplication.
 *
 * The possibility of using precomputed estimates is mentioned in "Guide to Elliptic Curve
 * Cryptography" (Hankerson, Menezes, Vanstone) in section 3.5.
 *
 * The derivation is described in the paper "Efficient Software Implementation of Public-Key
 * Cryptography on Sensor Networks Using the MSP430X Microcontroller" (Gouvea, Oliveira, Lopez),
 * Section 4.3 (here we use a somewhat higher-precision estimate):
 * d = a1*b2 - b1*a2
 * g1 = round((2^272)*b2/d)
 * g2 = round((2^272)*b1/d)
 *
 * (Note that 'd' is also equal to the curve order here because [a1,b1] and [a2,b2] are found
 * as outputs of the Extended Euclidean Algorithm on inputs 'order' and 'lambda').
 *
 * The function below splits a in r1 and r2, such that r1 + lambda * r2 == a (mod order).
 */

static void hsk_secp256k1_scalar_split_lambda(hsk_secp256k1_scalar *r1, hsk_secp256k1_scalar *r2, const hsk_secp256k1_scalar *a) {
    hsk_secp256k1_scalar c1, c2;
    static const hsk_secp256k1_scalar minus_lambda = HSK_SECP256K1_SCALAR_CONST(
        0xAC9C52B3UL, 0x3FA3CF1FUL, 0x5AD9E3FDUL, 0x77ED9BA4UL,
        0xA880B9FCUL, 0x8EC739C2UL, 0xE0CFC810UL, 0xB51283CFUL
    );
    static const hsk_secp256k1_scalar minus_b1 = HSK_SECP256K1_SCALAR_CONST(
        0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
        0xE4437ED6UL, 0x010E8828UL, 0x6F547FA9UL, 0x0ABFE4C3UL
    );
    static const hsk_secp256k1_scalar minus_b2 = HSK_SECP256K1_SCALAR_CONST(
        0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL,
        0x8A280AC5UL, 0x0774346DUL, 0xD765CDA8UL, 0x3DB1562CUL
    );
    static const hsk_secp256k1_scalar g1 = HSK_SECP256K1_SCALAR_CONST(
        0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00003086UL,
        0xD221A7D4UL, 0x6BCDE86CUL, 0x90E49284UL, 0xEB153DABUL
    );
    static const hsk_secp256k1_scalar g2 = HSK_SECP256K1_SCALAR_CONST(
        0x00000000UL, 0x00000000UL, 0x00000000UL, 0x0000E443UL,
        0x7ED6010EUL, 0x88286F54UL, 0x7FA90ABFUL, 0xE4C42212UL
    );
    VERIFY_CHECK(r1 != a);
    VERIFY_CHECK(r2 != a);
    /* these _var calls are constant time since the shift amount is constant */
    hsk_secp256k1_scalar_mul_shift_var(&c1, a, &g1, 272);
    hsk_secp256k1_scalar_mul_shift_var(&c2, a, &g2, 272);
    hsk_secp256k1_scalar_mul(&c1, &c1, &minus_b1);
    hsk_secp256k1_scalar_mul(&c2, &c2, &minus_b2);
    hsk_secp256k1_scalar_add(r2, &c1, &c2);
    hsk_secp256k1_scalar_mul(r1, r2, &minus_lambda);
    hsk_secp256k1_scalar_add(r1, r1, a);
}
#endif
#endif

#endif /* HSK_SECP256K1_SCALAR_IMPL_H */
