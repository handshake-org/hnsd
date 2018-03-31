/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HSK_SECP256K1_SCALAR_H
#define HSK_SECP256K1_SCALAR_H

#include "num.h"

#if defined HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(EXHAUSTIVE_TEST_ORDER)
#include "scalar_low.h"
#elif defined(HSK_USE_SCALAR_4X64)
#include "scalar_4x64.h"
#elif defined(HSK_USE_SCALAR_8X32)
#include "scalar_8x32.h"
#else
#error "Please select scalar implementation"
#endif

/** Clear a scalar to prevent the leak of sensitive data. */
static void hsk_secp256k1_scalar_clear(hsk_secp256k1_scalar *r);

/** Access bits from a scalar. All requested bits must belong to the same 32-bit limb. */
static unsigned int hsk_secp256k1_scalar_get_bits(const hsk_secp256k1_scalar *a, unsigned int offset, unsigned int count);

/** Access bits from a scalar. Not constant time. */
static unsigned int hsk_secp256k1_scalar_get_bits_var(const hsk_secp256k1_scalar *a, unsigned int offset, unsigned int count);

/** Set a scalar from a big endian byte array. */
static void hsk_secp256k1_scalar_set_b32(hsk_secp256k1_scalar *r, const unsigned char *bin, int *overflow);

/** Set a scalar to an unsigned integer. */
static void hsk_secp256k1_scalar_set_int(hsk_secp256k1_scalar *r, unsigned int v);

/** Convert a scalar to a byte array. */
static void hsk_secp256k1_scalar_get_b32(unsigned char *bin, const hsk_secp256k1_scalar* a);

/** Add two scalars together (modulo the group order). Returns whether it overflowed. */
static int hsk_secp256k1_scalar_add(hsk_secp256k1_scalar *r, const hsk_secp256k1_scalar *a, const hsk_secp256k1_scalar *b);

/** Conditionally add a power of two to a scalar. The result is not allowed to overflow. */
static void hsk_secp256k1_scalar_cadd_bit(hsk_secp256k1_scalar *r, unsigned int bit, int flag);

/** Multiply two scalars (modulo the group order). */
static void hsk_secp256k1_scalar_mul(hsk_secp256k1_scalar *r, const hsk_secp256k1_scalar *a, const hsk_secp256k1_scalar *b);

/** Shift a scalar right by some amount strictly between 0 and 16, returning
 *  the low bits that were shifted off */
static int hsk_secp256k1_scalar_shr_int(hsk_secp256k1_scalar *r, int n);

/** Compute the square of a scalar (modulo the group order). */
static void hsk_secp256k1_scalar_sqr(hsk_secp256k1_scalar *r, const hsk_secp256k1_scalar *a);

/** Compute the inverse of a scalar (modulo the group order). */
static void hsk_secp256k1_scalar_inverse(hsk_secp256k1_scalar *r, const hsk_secp256k1_scalar *a);

/** Compute the inverse of a scalar (modulo the group order), without constant-time guarantee. */
static void hsk_secp256k1_scalar_inverse_var(hsk_secp256k1_scalar *r, const hsk_secp256k1_scalar *a);

/** Compute the complement of a scalar (modulo the group order). */
static void hsk_secp256k1_scalar_negate(hsk_secp256k1_scalar *r, const hsk_secp256k1_scalar *a);

/** Check whether a scalar equals zero. */
static int hsk_secp256k1_scalar_is_zero(const hsk_secp256k1_scalar *a);

/** Check whether a scalar equals one. */
static int hsk_secp256k1_scalar_is_one(const hsk_secp256k1_scalar *a);

/** Check whether a scalar, considered as an nonnegative integer, is even. */
static int hsk_secp256k1_scalar_is_even(const hsk_secp256k1_scalar *a);

/** Check whether a scalar is higher than the group order divided by 2. */
static int hsk_secp256k1_scalar_is_high(const hsk_secp256k1_scalar *a);

/** Conditionally negate a number, in constant time.
 * Returns -1 if the number was negated, 1 otherwise */
static int hsk_secp256k1_scalar_cond_negate(hsk_secp256k1_scalar *a, int flag);

/** Compare two scalars. */
static int hsk_secp256k1_scalar_eq(const hsk_secp256k1_scalar *a, const hsk_secp256k1_scalar *b);

#ifdef HSK_USE_ENDOMORPHISM
/** Find r1 and r2 such that r1+r2*2^128 = a. */
static void hsk_secp256k1_scalar_split_128(hsk_secp256k1_scalar *r1, hsk_secp256k1_scalar *r2, const hsk_secp256k1_scalar *a);
/** Find r1 and r2 such that r1+r2*lambda = a, and r1 and r2 are maximum 128 bits long (see hsk_secp256k1_gej_mul_lambda). */
static void hsk_secp256k1_scalar_split_lambda(hsk_secp256k1_scalar *r1, hsk_secp256k1_scalar *r2, const hsk_secp256k1_scalar *a);
#endif

/** Multiply a and b (without taking the modulus!), divide by 2**shift, and round to the nearest integer. Shift must be at least 256. */
static void hsk_secp256k1_scalar_mul_shift_var(hsk_secp256k1_scalar *r, const hsk_secp256k1_scalar *a, const hsk_secp256k1_scalar *b, unsigned int shift);

#endif /* HSK_SECP256K1_SCALAR_H */
