/*****************************************************************************
 * Copyright (c) 2013, 2014, 2017 Pieter Wuille, Andrew Poelstra, Jonas Nick *
 * Distributed under the MIT software license, see the accompanying          *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.       *
 *****************************************************************************/

#ifndef HSK_SECP256K1_ECMULT_IMPL_H
#define HSK_SECP256K1_ECMULT_IMPL_H

#include <string.h>
#include <stdint.h>

#include "group.h"
#include "scalar.h"
#include "ecmult.h"

#if defined(EXHAUSTIVE_TEST_ORDER)
/* We need to lower these values for exhaustive tests because
 * the tables cannot have infinities in them (this breaks the
 * affine-isomorphism stuff which tracks z-ratios) */
#  if EXHAUSTIVE_TEST_ORDER > 128
#    define WINDOW_A 5
#    define WINDOW_G 8
#  elif EXHAUSTIVE_TEST_ORDER > 8
#    define WINDOW_A 4
#    define WINDOW_G 4
#  else
#    define WINDOW_A 2
#    define WINDOW_G 2
#  endif
#else
/* optimal for 128-bit and 256-bit exponents. */
#define WINDOW_A 5
/** larger numbers may result in slightly better performance, at the cost of
    exponentially larger precomputed tables. */
#ifdef HSK_USE_ENDOMORPHISM
/** Two tables for window size 15: 1.375 MiB. */
#define WINDOW_G 15
#else
/** One table for window size 16: 1.375 MiB. */
#define WINDOW_G 16
#endif
#endif

#ifdef HSK_USE_ENDOMORPHISM
    #define WNAF_BITS 128
#else
    #define WNAF_BITS 256
#endif
#define WNAF_SIZE(w) ((WNAF_BITS + (w) - 1) / (w))

/** The number of entries a table with precomputed multiples needs to have. */
#define ECMULT_TABLE_SIZE(w) (1 << ((w)-2))

/* The number of objects allocated on the scratch space for ecmult_multi algorithms */
#define PIPPENGER_SCRATCH_OBJECTS 6
#define STRAUSS_SCRATCH_OBJECTS 6

#define PIPPENGER_MAX_BUCKET_WINDOW 12

/* Minimum number of points for which pippenger_wnaf is faster than strauss wnaf */
#ifdef HSK_USE_ENDOMORPHISM
    #define ECMULT_PIPPENGER_THRESHOLD 88
#else
    #define ECMULT_PIPPENGER_THRESHOLD 160
#endif

#ifdef HSK_USE_ENDOMORPHISM
    #define ECMULT_MAX_POINTS_PER_BATCH 5000000
#else
    #define ECMULT_MAX_POINTS_PER_BATCH 10000000
#endif

/** Fill a table 'prej' with precomputed odd multiples of a. Prej will contain
 *  the values [1*a,3*a,...,(2*n-1)*a], so it space for n values. zr[0] will
 *  contain prej[0].z / a.z. The other zr[i] values = prej[i].z / prej[i-1].z.
 *  Prej's Z values are undefined, except for the last value.
 */
static void hsk_secp256k1_ecmult_odd_multiples_table(int n, hsk_secp256k1_gej *prej, hsk_secp256k1_fe *zr, const hsk_secp256k1_gej *a) {
    hsk_secp256k1_gej d;
    hsk_secp256k1_ge a_ge, d_ge;
    int i;

    VERIFY_CHECK(!a->infinity);

    hsk_secp256k1_gej_double_var(&d, a, NULL);

    /*
     * Perform the additions on an isomorphism where 'd' is affine: drop the z coordinate
     * of 'd', and scale the 1P starting value's x/y coordinates without changing its z.
     */
    d_ge.x = d.x;
    d_ge.y = d.y;
    d_ge.infinity = 0;

    hsk_secp256k1_ge_set_gej_zinv(&a_ge, a, &d.z);
    prej[0].x = a_ge.x;
    prej[0].y = a_ge.y;
    prej[0].z = a->z;
    prej[0].infinity = 0;

    zr[0] = d.z;
    for (i = 1; i < n; i++) {
        hsk_secp256k1_gej_add_ge_var(&prej[i], &prej[i-1], &d_ge, &zr[i]);
    }

    /*
     * Each point in 'prej' has a z coordinate too small by a factor of 'd.z'. Only
     * the final point's z coordinate is actually used though, so just update that.
     */
    hsk_secp256k1_fe_mul(&prej[n-1].z, &prej[n-1].z, &d.z);
}

/** Fill a table 'pre' with precomputed odd multiples of a.
 *
 *  There are two versions of this function:
 *  - hsk_secp256k1_ecmult_odd_multiples_table_globalz_windowa which brings its
 *    resulting point set to a single constant Z denominator, stores the X and Y
 *    coordinates as ge_storage points in pre, and stores the global Z in rz.
 *    It only operates on tables sized for WINDOW_A wnaf multiples.
 *  - hsk_secp256k1_ecmult_odd_multiples_table_storage_var, which converts its
 *    resulting point set to actually affine points, and stores those in pre.
 *    It operates on tables of any size, but uses heap-allocated temporaries.
 *
 *  To compute a*P + b*G, we compute a table for P using the first function,
 *  and for G using the second (which requires an inverse, but it only needs to
 *  happen once).
 */
static void hsk_secp256k1_ecmult_odd_multiples_table_globalz_windowa(hsk_secp256k1_ge *pre, hsk_secp256k1_fe *globalz, const hsk_secp256k1_gej *a) {
    hsk_secp256k1_gej prej[ECMULT_TABLE_SIZE(WINDOW_A)];
    hsk_secp256k1_fe zr[ECMULT_TABLE_SIZE(WINDOW_A)];

    /* Compute the odd multiples in Jacobian form. */
    hsk_secp256k1_ecmult_odd_multiples_table(ECMULT_TABLE_SIZE(WINDOW_A), prej, zr, a);
    /* Bring them to the same Z denominator. */
    hsk_secp256k1_ge_globalz_set_table_gej(ECMULT_TABLE_SIZE(WINDOW_A), pre, globalz, prej, zr);
}

static void hsk_secp256k1_ecmult_odd_multiples_table_storage_var(int n, hsk_secp256k1_ge_storage *pre, const hsk_secp256k1_gej *a, const hsk_secp256k1_callback *cb) {
    hsk_secp256k1_gej *prej = (hsk_secp256k1_gej*)checked_malloc(cb, sizeof(hsk_secp256k1_gej) * n);
    hsk_secp256k1_ge *prea = (hsk_secp256k1_ge*)checked_malloc(cb, sizeof(hsk_secp256k1_ge) * n);
    hsk_secp256k1_fe *zr = (hsk_secp256k1_fe*)checked_malloc(cb, sizeof(hsk_secp256k1_fe) * n);
    int i;

    /* Compute the odd multiples in Jacobian form. */
    hsk_secp256k1_ecmult_odd_multiples_table(n, prej, zr, a);
    /* Convert them in batch to affine coordinates. */
    hsk_secp256k1_ge_set_table_gej_var(prea, prej, zr, n);
    /* Convert them to compact storage form. */
    for (i = 0; i < n; i++) {
        hsk_secp256k1_ge_to_storage(&pre[i], &prea[i]);
    }

    free(prea);
    free(prej);
    free(zr);
}

/** The following two macro retrieves a particular odd multiple from a table
 *  of precomputed multiples. */
#define ECMULT_TABLE_GET_GE(r,pre,n,w) do { \
    VERIFY_CHECK(((n) & 1) == 1); \
    VERIFY_CHECK((n) >= -((1 << ((w)-1)) - 1)); \
    VERIFY_CHECK((n) <=  ((1 << ((w)-1)) - 1)); \
    if ((n) > 0) { \
        *(r) = (pre)[((n)-1)/2]; \
    } else { \
        hsk_secp256k1_ge_neg((r), &(pre)[(-(n)-1)/2]); \
    } \
} while(0)

#define ECMULT_TABLE_GET_GE_STORAGE(r,pre,n,w) do { \
    VERIFY_CHECK(((n) & 1) == 1); \
    VERIFY_CHECK((n) >= -((1 << ((w)-1)) - 1)); \
    VERIFY_CHECK((n) <=  ((1 << ((w)-1)) - 1)); \
    if ((n) > 0) { \
        hsk_secp256k1_ge_from_storage((r), &(pre)[((n)-1)/2]); \
    } else { \
        hsk_secp256k1_ge_from_storage((r), &(pre)[(-(n)-1)/2]); \
        hsk_secp256k1_ge_neg((r), (r)); \
    } \
} while(0)

static void hsk_secp256k1_ecmult_context_init(hsk_secp256k1_ecmult_context *ctx) {
    ctx->pre_g = NULL;
#ifdef HSK_USE_ENDOMORPHISM
    ctx->pre_g_128 = NULL;
#endif
}

static void hsk_secp256k1_ecmult_context_build(hsk_secp256k1_ecmult_context *ctx, const hsk_secp256k1_callback *cb) {
    hsk_secp256k1_gej gj;

    if (ctx->pre_g != NULL) {
        return;
    }

    /* get the generator */
    hsk_secp256k1_gej_set_ge(&gj, &hsk_secp256k1_ge_const_g);

    ctx->pre_g = (hsk_secp256k1_ge_storage (*)[])checked_malloc(cb, sizeof((*ctx->pre_g)[0]) * ECMULT_TABLE_SIZE(WINDOW_G));

    /* precompute the tables with odd multiples */
    hsk_secp256k1_ecmult_odd_multiples_table_storage_var(ECMULT_TABLE_SIZE(WINDOW_G), *ctx->pre_g, &gj, cb);

#ifdef HSK_USE_ENDOMORPHISM
    {
        hsk_secp256k1_gej g_128j;
        int i;

        ctx->pre_g_128 = (hsk_secp256k1_ge_storage (*)[])checked_malloc(cb, sizeof((*ctx->pre_g_128)[0]) * ECMULT_TABLE_SIZE(WINDOW_G));

        /* calculate 2^128*generator */
        g_128j = gj;
        for (i = 0; i < 128; i++) {
            hsk_secp256k1_gej_double_var(&g_128j, &g_128j, NULL);
        }
        hsk_secp256k1_ecmult_odd_multiples_table_storage_var(ECMULT_TABLE_SIZE(WINDOW_G), *ctx->pre_g_128, &g_128j, cb);
    }
#endif
}

static void hsk_secp256k1_ecmult_context_clone(hsk_secp256k1_ecmult_context *dst,
                                           const hsk_secp256k1_ecmult_context *src, const hsk_secp256k1_callback *cb) {
    if (src->pre_g == NULL) {
        dst->pre_g = NULL;
    } else {
        size_t size = sizeof((*dst->pre_g)[0]) * ECMULT_TABLE_SIZE(WINDOW_G);
        dst->pre_g = (hsk_secp256k1_ge_storage (*)[])checked_malloc(cb, size);
        memcpy(dst->pre_g, src->pre_g, size);
    }
#ifdef HSK_USE_ENDOMORPHISM
    if (src->pre_g_128 == NULL) {
        dst->pre_g_128 = NULL;
    } else {
        size_t size = sizeof((*dst->pre_g_128)[0]) * ECMULT_TABLE_SIZE(WINDOW_G);
        dst->pre_g_128 = (hsk_secp256k1_ge_storage (*)[])checked_malloc(cb, size);
        memcpy(dst->pre_g_128, src->pre_g_128, size);
    }
#endif
}

static int hsk_secp256k1_ecmult_context_is_built(const hsk_secp256k1_ecmult_context *ctx) {
    return ctx->pre_g != NULL;
}

static void hsk_secp256k1_ecmult_context_clear(hsk_secp256k1_ecmult_context *ctx) {
    free(ctx->pre_g);
#ifdef HSK_USE_ENDOMORPHISM
    free(ctx->pre_g_128);
#endif
    hsk_secp256k1_ecmult_context_init(ctx);
}

/** Convert a number to WNAF notation. The number becomes represented by sum(2^i * wnaf[i], i=0..bits),
 *  with the following guarantees:
 *  - each wnaf[i] is either 0, or an odd integer between -(1<<(w-1) - 1) and (1<<(w-1) - 1)
 *  - two non-zero entries in wnaf are separated by at least w-1 zeroes.
 *  - the number of set values in wnaf is returned. This number is at most 256, and at most one more
 *    than the number of bits in the (absolute value) of the input.
 */
static int hsk_secp256k1_ecmult_wnaf(int *wnaf, int len, const hsk_secp256k1_scalar *a, int w) {
    hsk_secp256k1_scalar s = *a;
    int last_set_bit = -1;
    int bit = 0;
    int sign = 1;
    int carry = 0;

    VERIFY_CHECK(wnaf != NULL);
    VERIFY_CHECK(0 <= len && len <= 256);
    VERIFY_CHECK(a != NULL);
    VERIFY_CHECK(2 <= w && w <= 31);

    memset(wnaf, 0, len * sizeof(wnaf[0]));

    if (hsk_secp256k1_scalar_get_bits(&s, 255, 1)) {
        hsk_secp256k1_scalar_negate(&s, &s);
        sign = -1;
    }

    while (bit < len) {
        int now;
        int word;
        if (hsk_secp256k1_scalar_get_bits(&s, bit, 1) == (unsigned int)carry) {
            bit++;
            continue;
        }

        now = w;
        if (now > len - bit) {
            now = len - bit;
        }

        word = hsk_secp256k1_scalar_get_bits_var(&s, bit, now) + carry;

        carry = (word >> (w-1)) & 1;
        word -= carry << w;

        wnaf[bit] = sign * word;
        last_set_bit = bit;

        bit += now;
    }
#ifdef VERIFY
    CHECK(carry == 0);
    while (bit < 256) {
        CHECK(hsk_secp256k1_scalar_get_bits(&s, bit++, 1) == 0);
    }
#endif
    return last_set_bit + 1;
}

struct hsk_secp256k1_strauss_point_state {
#ifdef HSK_USE_ENDOMORPHISM
    hsk_secp256k1_scalar na_1, na_lam;
    int wnaf_na_1[130];
    int wnaf_na_lam[130];
    int bits_na_1;
    int bits_na_lam;
#else
    int wnaf_na[256];
    int bits_na;
#endif
    size_t input_pos;
};

struct hsk_secp256k1_strauss_state {
    hsk_secp256k1_gej* prej;
    hsk_secp256k1_fe* zr;
    hsk_secp256k1_ge* pre_a;
#ifdef HSK_USE_ENDOMORPHISM
    hsk_secp256k1_ge* pre_a_lam;
#endif
    struct hsk_secp256k1_strauss_point_state* ps;
};

static void hsk_secp256k1_ecmult_strauss_wnaf(const hsk_secp256k1_ecmult_context *ctx, const struct hsk_secp256k1_strauss_state *state, hsk_secp256k1_gej *r, int num, const hsk_secp256k1_gej *a, const hsk_secp256k1_scalar *na, const hsk_secp256k1_scalar *ng) {
    hsk_secp256k1_ge tmpa;
    hsk_secp256k1_fe Z;
#ifdef HSK_USE_ENDOMORPHISM
    /* Splitted G factors. */
    hsk_secp256k1_scalar ng_1, ng_128;
    int wnaf_ng_1[129];
    int bits_ng_1 = 0;
    int wnaf_ng_128[129];
    int bits_ng_128 = 0;
#else
    int wnaf_ng[256];
    int bits_ng = 0;
#endif
    int i;
    int bits = 0;
    int np;
    int no = 0;

    for (np = 0; np < num; ++np) {
        if (hsk_secp256k1_scalar_is_zero(&na[np]) || hsk_secp256k1_gej_is_infinity(&a[np])) {
            continue;
        }
        state->ps[no].input_pos = np;
#ifdef HSK_USE_ENDOMORPHISM
        /* split na into na_1 and na_lam (where na = na_1 + na_lam*lambda, and na_1 and na_lam are ~128 bit) */
        hsk_secp256k1_scalar_split_lambda(&state->ps[no].na_1, &state->ps[no].na_lam, &na[np]);

        /* build wnaf representation for na_1 and na_lam. */
        state->ps[no].bits_na_1   = hsk_secp256k1_ecmult_wnaf(state->ps[no].wnaf_na_1,   130, &state->ps[no].na_1,   WINDOW_A);
        state->ps[no].bits_na_lam = hsk_secp256k1_ecmult_wnaf(state->ps[no].wnaf_na_lam, 130, &state->ps[no].na_lam, WINDOW_A);
        VERIFY_CHECK(state->ps[no].bits_na_1 <= 130);
        VERIFY_CHECK(state->ps[no].bits_na_lam <= 130);
        if (state->ps[no].bits_na_1 > bits) {
            bits = state->ps[no].bits_na_1;
        }
        if (state->ps[no].bits_na_lam > bits) {
            bits = state->ps[no].bits_na_lam;
        }
#else
        /* build wnaf representation for na. */
        state->ps[no].bits_na     = hsk_secp256k1_ecmult_wnaf(state->ps[no].wnaf_na,     256, &na[np],      WINDOW_A);
        if (state->ps[no].bits_na > bits) {
            bits = state->ps[no].bits_na;
        }
#endif
        ++no;
    }

    /* Calculate odd multiples of a.
     * All multiples are brought to the same Z 'denominator', which is stored
     * in Z. Due to secp256k1' isomorphism we can do all operations pretending
     * that the Z coordinate was 1, use affine addition formulae, and correct
     * the Z coordinate of the result once at the end.
     * The exception is the precomputed G table points, which are actually
     * affine. Compared to the base used for other points, they have a Z ratio
     * of 1/Z, so we can use hsk_secp256k1_gej_add_zinv_var, which uses the same
     * isomorphism to efficiently add with a known Z inverse.
     */
    if (no > 0) {
        /* Compute the odd multiples in Jacobian form. */
        hsk_secp256k1_ecmult_odd_multiples_table(ECMULT_TABLE_SIZE(WINDOW_A), state->prej, state->zr, &a[state->ps[0].input_pos]);
        for (np = 1; np < no; ++np) {
            hsk_secp256k1_gej tmp = a[state->ps[np].input_pos];
#ifdef VERIFY
            hsk_secp256k1_fe_normalize_var(&(state->prej[(np - 1) * ECMULT_TABLE_SIZE(WINDOW_A) + ECMULT_TABLE_SIZE(WINDOW_A) - 1].z));
#endif
            hsk_secp256k1_gej_rescale(&tmp, &(state->prej[(np - 1) * ECMULT_TABLE_SIZE(WINDOW_A) + ECMULT_TABLE_SIZE(WINDOW_A) - 1].z));
            hsk_secp256k1_ecmult_odd_multiples_table(ECMULT_TABLE_SIZE(WINDOW_A), state->prej + np * ECMULT_TABLE_SIZE(WINDOW_A), state->zr + np * ECMULT_TABLE_SIZE(WINDOW_A), &tmp);
            hsk_secp256k1_fe_mul(state->zr + np * ECMULT_TABLE_SIZE(WINDOW_A), state->zr + np * ECMULT_TABLE_SIZE(WINDOW_A), &(a[state->ps[np].input_pos].z));
        }
        /* Bring them to the same Z denominator. */
        hsk_secp256k1_ge_globalz_set_table_gej(ECMULT_TABLE_SIZE(WINDOW_A) * no, state->pre_a, &Z, state->prej, state->zr);
    } else {
        hsk_secp256k1_fe_set_int(&Z, 1);
    }

#ifdef HSK_USE_ENDOMORPHISM
    for (np = 0; np < no; ++np) {
        for (i = 0; i < ECMULT_TABLE_SIZE(WINDOW_A); i++) {
            hsk_secp256k1_ge_mul_lambda(&state->pre_a_lam[np * ECMULT_TABLE_SIZE(WINDOW_A) + i], &state->pre_a[np * ECMULT_TABLE_SIZE(WINDOW_A) + i]);
        }
    }

    if (ng) {
        /* split ng into ng_1 and ng_128 (where gn = gn_1 + gn_128*2^128, and gn_1 and gn_128 are ~128 bit) */
        hsk_secp256k1_scalar_split_128(&ng_1, &ng_128, ng);

        /* Build wnaf representation for ng_1 and ng_128 */
        bits_ng_1   = hsk_secp256k1_ecmult_wnaf(wnaf_ng_1,   129, &ng_1,   WINDOW_G);
        bits_ng_128 = hsk_secp256k1_ecmult_wnaf(wnaf_ng_128, 129, &ng_128, WINDOW_G);
        if (bits_ng_1 > bits) {
            bits = bits_ng_1;
        }
        if (bits_ng_128 > bits) {
            bits = bits_ng_128;
        }
    }
#else
    if (ng) {
        bits_ng     = hsk_secp256k1_ecmult_wnaf(wnaf_ng,     256, ng,      WINDOW_G);
        if (bits_ng > bits) {
            bits = bits_ng;
        }
    }
#endif

    hsk_secp256k1_gej_set_infinity(r);

    for (i = bits - 1; i >= 0; i--) {
        int n;
        hsk_secp256k1_gej_double_var(r, r, NULL);
#ifdef HSK_USE_ENDOMORPHISM
        for (np = 0; np < no; ++np) {
            if (i < state->ps[np].bits_na_1 && (n = state->ps[np].wnaf_na_1[i])) {
                ECMULT_TABLE_GET_GE(&tmpa, state->pre_a + np * ECMULT_TABLE_SIZE(WINDOW_A), n, WINDOW_A);
                hsk_secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
            }
            if (i < state->ps[np].bits_na_lam && (n = state->ps[np].wnaf_na_lam[i])) {
                ECMULT_TABLE_GET_GE(&tmpa, state->pre_a_lam + np * ECMULT_TABLE_SIZE(WINDOW_A), n, WINDOW_A);
                hsk_secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
            }
        }
        if (i < bits_ng_1 && (n = wnaf_ng_1[i])) {
            ECMULT_TABLE_GET_GE_STORAGE(&tmpa, *ctx->pre_g, n, WINDOW_G);
            hsk_secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
        }
        if (i < bits_ng_128 && (n = wnaf_ng_128[i])) {
            ECMULT_TABLE_GET_GE_STORAGE(&tmpa, *ctx->pre_g_128, n, WINDOW_G);
            hsk_secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
        }
#else
        for (np = 0; np < no; ++np) {
            if (i < state->ps[np].bits_na && (n = state->ps[np].wnaf_na[i])) {
                ECMULT_TABLE_GET_GE(&tmpa, state->pre_a + np * ECMULT_TABLE_SIZE(WINDOW_A), n, WINDOW_A);
                hsk_secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
            }
        }
        if (i < bits_ng && (n = wnaf_ng[i])) {
            ECMULT_TABLE_GET_GE_STORAGE(&tmpa, *ctx->pre_g, n, WINDOW_G);
            hsk_secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
        }
#endif
    }

    if (!r->infinity) {
        hsk_secp256k1_fe_mul(&r->z, &r->z, &Z);
    }
}

static void hsk_secp256k1_ecmult(const hsk_secp256k1_ecmult_context *ctx, hsk_secp256k1_gej *r, const hsk_secp256k1_gej *a, const hsk_secp256k1_scalar *na, const hsk_secp256k1_scalar *ng) {
    hsk_secp256k1_gej prej[ECMULT_TABLE_SIZE(WINDOW_A)];
    hsk_secp256k1_fe zr[ECMULT_TABLE_SIZE(WINDOW_A)];
    hsk_secp256k1_ge pre_a[ECMULT_TABLE_SIZE(WINDOW_A)];
    struct hsk_secp256k1_strauss_point_state ps[1];
#ifdef HSK_USE_ENDOMORPHISM
    hsk_secp256k1_ge pre_a_lam[ECMULT_TABLE_SIZE(WINDOW_A)];
#endif
    struct hsk_secp256k1_strauss_state state;

    state.prej = prej;
    state.zr = zr;
    state.pre_a = pre_a;
#ifdef HSK_USE_ENDOMORPHISM
    state.pre_a_lam = pre_a_lam;
#endif
    state.ps = ps;
    hsk_secp256k1_ecmult_strauss_wnaf(ctx, &state, r, 1, a, na, ng);
}

static size_t hsk_secp256k1_strauss_scratch_size(size_t n_points) {
#ifdef HSK_USE_ENDOMORPHISM
    static const size_t point_size = (2 * sizeof(hsk_secp256k1_ge) + sizeof(hsk_secp256k1_gej) + sizeof(hsk_secp256k1_fe)) * ECMULT_TABLE_SIZE(WINDOW_A) + sizeof(struct hsk_secp256k1_strauss_point_state) + sizeof(hsk_secp256k1_gej) + sizeof(hsk_secp256k1_scalar);
#else
    static const size_t point_size = (sizeof(hsk_secp256k1_ge) + sizeof(hsk_secp256k1_gej) + sizeof(hsk_secp256k1_fe)) * ECMULT_TABLE_SIZE(WINDOW_A) + sizeof(struct hsk_secp256k1_strauss_point_state) + sizeof(hsk_secp256k1_gej) + sizeof(hsk_secp256k1_scalar);
#endif
    return n_points*point_size;
}

static int hsk_secp256k1_ecmult_strauss_batch(const hsk_secp256k1_ecmult_context *ctx, hsk_secp256k1_scratch *scratch, hsk_secp256k1_gej *r, const hsk_secp256k1_scalar *inp_g_sc, hsk_secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n_points, size_t cb_offset) {
    hsk_secp256k1_gej* points;
    hsk_secp256k1_scalar* scalars;
    struct hsk_secp256k1_strauss_state state;
    size_t i;

    hsk_secp256k1_gej_set_infinity(r);
    if (inp_g_sc == NULL && n_points == 0) {
        return 1;
    }

    if (!hsk_secp256k1_scratch_resize(scratch, hsk_secp256k1_strauss_scratch_size(n_points), STRAUSS_SCRATCH_OBJECTS)) {
        return 0;
    }
    hsk_secp256k1_scratch_reset(scratch);
    points = (hsk_secp256k1_gej*)hsk_secp256k1_scratch_alloc(scratch, n_points * sizeof(hsk_secp256k1_gej));
    scalars = (hsk_secp256k1_scalar*)hsk_secp256k1_scratch_alloc(scratch, n_points * sizeof(hsk_secp256k1_scalar));
    state.prej = (hsk_secp256k1_gej*)hsk_secp256k1_scratch_alloc(scratch, n_points * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(hsk_secp256k1_gej));
    state.zr = (hsk_secp256k1_fe*)hsk_secp256k1_scratch_alloc(scratch, n_points * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(hsk_secp256k1_fe));
#ifdef HSK_USE_ENDOMORPHISM
    state.pre_a = (hsk_secp256k1_ge*)hsk_secp256k1_scratch_alloc(scratch, n_points * 2 * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(hsk_secp256k1_ge));
    state.pre_a_lam = state.pre_a + n_points * ECMULT_TABLE_SIZE(WINDOW_A);
#else
    state.pre_a = (hsk_secp256k1_ge*)hsk_secp256k1_scratch_alloc(scratch, n_points * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(hsk_secp256k1_ge));
#endif
    state.ps = (struct hsk_secp256k1_strauss_point_state*)hsk_secp256k1_scratch_alloc(scratch, n_points * sizeof(struct hsk_secp256k1_strauss_point_state));

    for (i = 0; i < n_points; i++) {
        hsk_secp256k1_ge point;
        if (!cb(&scalars[i], &point, i+cb_offset, cbdata)) return 0;
        hsk_secp256k1_gej_set_ge(&points[i], &point);
    }
    hsk_secp256k1_ecmult_strauss_wnaf(ctx, &state, r, n_points, points, scalars, inp_g_sc);
    return 1;
}

/* Wrapper for hsk_secp256k1_ecmult_multi_func interface */
static int hsk_secp256k1_ecmult_strauss_batch_single(const hsk_secp256k1_ecmult_context *actx, hsk_secp256k1_scratch *scratch, hsk_secp256k1_gej *r, const hsk_secp256k1_scalar *inp_g_sc, hsk_secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n) {
    return hsk_secp256k1_ecmult_strauss_batch(actx, scratch, r, inp_g_sc, cb, cbdata, n, 0);
}

static size_t hsk_secp256k1_strauss_max_points(hsk_secp256k1_scratch *scratch) {
    return hsk_secp256k1_scratch_max_allocation(scratch, STRAUSS_SCRATCH_OBJECTS) / hsk_secp256k1_strauss_scratch_size(1);
}

/** Convert a number to WNAF notation.
 *  The number becomes represented by sum(2^{wi} * wnaf[i], i=0..WNAF_SIZE(w)+1) - return_val.
 *  It has the following guarantees:
 *  - each wnaf[i] is either 0 or an odd integer between -(1 << w) and (1 << w)
 *  - the number of words set is always WNAF_SIZE(w)
 *  - the returned skew is 0 without endomorphism, or 0 or 1 with endomorphism
 */
static int hsk_secp256k1_wnaf_fixed(int *wnaf, const hsk_secp256k1_scalar *s, int w) {
    int sign = 0;
    int skew = 0;
    int pos = 1;
#ifndef HSK_USE_ENDOMORPHISM
    hsk_secp256k1_scalar neg_s;
#endif
    const hsk_secp256k1_scalar *work = s;

    if (hsk_secp256k1_scalar_is_zero(s)) {
        while (pos * w < WNAF_BITS) {
            wnaf[pos] = 0;
            ++pos;
        }
        return 0;
    }

    if (hsk_secp256k1_scalar_is_even(s)) {
#ifdef HSK_USE_ENDOMORPHISM
        skew = 1;
#else
        hsk_secp256k1_scalar_negate(&neg_s, s);
        work = &neg_s;
        sign = -1;
#endif
    }

    wnaf[0] = (hsk_secp256k1_scalar_get_bits_var(work, 0, w) + skew + sign) ^ sign;

    while (pos * w < WNAF_BITS) {
        int now = w;
        int val;
        if (now + pos * w > WNAF_BITS) {
            now = WNAF_BITS - pos * w;
        }
        val = hsk_secp256k1_scalar_get_bits_var(work, pos * w, now);
        if ((val & 1) == 0) {
            wnaf[pos - 1] -= ((1 << w) + sign) ^ sign;
            wnaf[pos] = (val + 1 + sign) ^ sign;
        } else {
            wnaf[pos] = (val + sign) ^ sign;
        }
        ++pos;
    }
    VERIFY_CHECK(pos == WNAF_SIZE(w));

    return skew;
}

struct hsk_secp256k1_pippenger_point_state {
    int skew_na;
    size_t input_pos;
};

struct hsk_secp256k1_pippenger_state {
    int *wnaf_na;
    struct hsk_secp256k1_pippenger_point_state* ps;
};

/*
 * pippenger_wnaf computes the result of a multi-point multiplication as
 * follows: The scalars are brought into wnaf with n_wnaf elements each. Then
 * for every i < n_wnaf, first each point is added to a "bucket" corresponding
 * to the point's wnaf[i]. Second, the buckets are added together such that
 * r += 1*bucket[0] + 3*bucket[1] + 5*bucket[2] + ...
 */
static int hsk_secp256k1_ecmult_pippenger_wnaf(hsk_secp256k1_gej *buckets, int bucket_window, struct hsk_secp256k1_pippenger_state *state, hsk_secp256k1_gej *r, hsk_secp256k1_scalar *sc, hsk_secp256k1_ge *pt, size_t num) {
    size_t n_wnaf = WNAF_SIZE(bucket_window+1);
    size_t np;
    size_t no = 0;
    int i;
    int j;

    for (np = 0; np < num; ++np) {
        if (hsk_secp256k1_scalar_is_zero(&sc[np]) || hsk_secp256k1_ge_is_infinity(&pt[np])) {
            continue;
        }
        state->ps[no].input_pos = np;
        state->ps[no].skew_na = hsk_secp256k1_wnaf_fixed(&state->wnaf_na[no*n_wnaf], &sc[np], bucket_window+1);
        no++;
    }
    hsk_secp256k1_gej_set_infinity(r);

    if (no == 0) {
        return 1;
    }

    for (i = n_wnaf - 1; i >= 0; i--) {
        hsk_secp256k1_gej running_sum;

        for(j = 0; j < ECMULT_TABLE_SIZE(bucket_window+2); j++) {
            hsk_secp256k1_gej_set_infinity(&buckets[j]);
        }

        for (np = 0; np < no; ++np) {
            int n = state->wnaf_na[np*n_wnaf + i];
            struct hsk_secp256k1_pippenger_point_state point_state = state->ps[np];
            hsk_secp256k1_ge tmp;
            int idx;

#ifdef HSK_USE_ENDOMORPHISM
            if (i == 0) {
                /* correct for wnaf skew */
                int skew = point_state.skew_na;
                if (skew) {
                    hsk_secp256k1_ge_neg(&tmp, &pt[point_state.input_pos]);
                    hsk_secp256k1_gej_add_ge_var(&buckets[0], &buckets[0], &tmp, NULL);
                }
            }
#endif
            if (n > 0) {
                idx = (n - 1)/2;
                hsk_secp256k1_gej_add_ge_var(&buckets[idx], &buckets[idx], &pt[point_state.input_pos], NULL);
            } else if (n < 0) {
                idx = -(n + 1)/2;
                hsk_secp256k1_ge_neg(&tmp, &pt[point_state.input_pos]);
                hsk_secp256k1_gej_add_ge_var(&buckets[idx], &buckets[idx], &tmp, NULL);
            }
        }

        for(j = 0; j < bucket_window; j++) {
            hsk_secp256k1_gej_double_var(r, r, NULL);
        }

        hsk_secp256k1_gej_set_infinity(&running_sum);
        /* Accumulate the sum: bucket[0] + 3*bucket[1] + 5*bucket[2] + 7*bucket[3] + ...
         *                   = bucket[0] +   bucket[1] +   bucket[2] +   bucket[3] + ...
         *                   +         2 *  (bucket[1] + 2*bucket[2] + 3*bucket[3] + ...)
         * using an intermediate running sum:
         * running_sum = bucket[0] +   bucket[1] +   bucket[2] + ...
         *
         * The doubling is done implicitly by deferring the final window doubling (of 'r').
         */
        for(j = ECMULT_TABLE_SIZE(bucket_window+2) - 1; j > 0; j--) {
            hsk_secp256k1_gej_add_var(&running_sum, &running_sum, &buckets[j], NULL);
            hsk_secp256k1_gej_add_var(r, r, &running_sum, NULL);
        }

        hsk_secp256k1_gej_add_var(&running_sum, &running_sum, &buckets[0], NULL);
        hsk_secp256k1_gej_double_var(r, r, NULL);
        hsk_secp256k1_gej_add_var(r, r, &running_sum, NULL);
    }
    return 1;
}

/**
 * Returns optimal bucket_window (number of bits of a scalar represented by a
 * set of buckets) for a given number of points.
 */
static int hsk_secp256k1_pippenger_bucket_window(size_t n) {
#ifdef HSK_USE_ENDOMORPHISM
    if (n <= 1) {
        return 1;
    } else if (n <= 4) {
        return 2;
    } else if (n <= 20) {
        return 3;
    } else if (n <= 57) {
        return 4;
    } else if (n <= 136) {
        return 5;
    } else if (n <= 235) {
        return 6;
    } else if (n <= 1260) {
        return 7;
    } else if (n <= 4420) {
        return 9;
    } else if (n <= 7880) {
        return 10;
    } else if (n <= 16050) {
        return 11;
    } else {
        return PIPPENGER_MAX_BUCKET_WINDOW;
    }
#else
    if (n <= 1) {
        return 1;
    } else if (n <= 11) {
        return 2;
    } else if (n <= 45) {
        return 3;
    } else if (n <= 100) {
        return 4;
    } else if (n <= 275) {
        return 5;
    } else if (n <= 625) {
        return 6;
    } else if (n <= 1850) {
        return 7;
    } else if (n <= 3400) {
        return 8;
    } else if (n <= 9630) {
        return 9;
    } else if (n <= 17900) {
        return 10;
    } else if (n <= 32800) {
        return 11;
    } else {
        return PIPPENGER_MAX_BUCKET_WINDOW;
    }
#endif
}

/**
 * Returns the maximum optimal number of points for a bucket_window.
 */
static size_t hsk_secp256k1_pippenger_bucket_window_inv(int bucket_window) {
    switch(bucket_window) {
#ifdef HSK_USE_ENDOMORPHISM
        case 1: return 1;
        case 2: return 4;
        case 3: return 20;
        case 4: return 57;
        case 5: return 136;
        case 6: return 235;
        case 7: return 1260;
        case 8: return 1260;
        case 9: return 4420;
        case 10: return 7880;
        case 11: return 16050;
        case PIPPENGER_MAX_BUCKET_WINDOW: return SIZE_MAX;
#else
        case 1: return 1;
        case 2: return 11;
        case 3: return 45;
        case 4: return 100;
        case 5: return 275;
        case 6: return 625;
        case 7: return 1850;
        case 8: return 3400;
        case 9: return 9630;
        case 10: return 17900;
        case 11: return 32800;
        case PIPPENGER_MAX_BUCKET_WINDOW: return SIZE_MAX;
#endif
    }
    return 0;
}


#ifdef HSK_USE_ENDOMORPHISM
HSK_SECP256K1_INLINE static void hsk_secp256k1_ecmult_endo_split(hsk_secp256k1_scalar *s1, hsk_secp256k1_scalar *s2, hsk_secp256k1_ge *p1, hsk_secp256k1_ge *p2) {
    hsk_secp256k1_scalar tmp = *s1;
    hsk_secp256k1_scalar_split_lambda(s1, s2, &tmp);
    hsk_secp256k1_ge_mul_lambda(p2, p1);

    if (hsk_secp256k1_scalar_is_high(s1)) {
        hsk_secp256k1_scalar_negate(s1, s1);
        hsk_secp256k1_ge_neg(p1, p1);
    }
    if (hsk_secp256k1_scalar_is_high(s2)) {
        hsk_secp256k1_scalar_negate(s2, s2);
        hsk_secp256k1_ge_neg(p2, p2);
    }
}
#endif

/**
 * Returns the scratch size required for a given number of points (excluding
 * base point G) without considering alignment.
 */
static size_t hsk_secp256k1_pippenger_scratch_size(size_t n_points, int bucket_window) {
#ifdef HSK_USE_ENDOMORPHISM
    size_t entries = 2*n_points + 2;
#else
    size_t entries = n_points + 1;
#endif
    size_t entry_size = sizeof(hsk_secp256k1_ge) + sizeof(hsk_secp256k1_scalar) + sizeof(struct hsk_secp256k1_pippenger_point_state) + (WNAF_SIZE(bucket_window+1)+1)*sizeof(int);
    return ((1<<bucket_window) * sizeof(hsk_secp256k1_gej) + sizeof(struct hsk_secp256k1_pippenger_state) + entries * entry_size);
}

static int hsk_secp256k1_ecmult_pippenger_batch(const hsk_secp256k1_ecmult_context *ctx, hsk_secp256k1_scratch *scratch, hsk_secp256k1_gej *r, const hsk_secp256k1_scalar *inp_g_sc, hsk_secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n_points, size_t cb_offset) {
    /* Use 2(n+1) with the endomorphism, n+1 without, when calculating batch
     * sizes. The reason for +1 is that we add the G scalar to the list of
     * other scalars. */
#ifdef HSK_USE_ENDOMORPHISM
    size_t entries = 2*n_points + 2;
#else
    size_t entries = n_points + 1;
#endif
    hsk_secp256k1_ge *points;
    hsk_secp256k1_scalar *scalars;
    hsk_secp256k1_gej *buckets;
    struct hsk_secp256k1_pippenger_state *state_space;
    size_t idx = 0;
    size_t point_idx = 0;
    int i, j;
    int bucket_window;

    (void)ctx;
    hsk_secp256k1_gej_set_infinity(r);
    if (inp_g_sc == NULL && n_points == 0) {
        return 1;
    }

    bucket_window = hsk_secp256k1_pippenger_bucket_window(n_points);
    if (!hsk_secp256k1_scratch_resize(scratch, hsk_secp256k1_pippenger_scratch_size(n_points, bucket_window), PIPPENGER_SCRATCH_OBJECTS)) {
        return 0;
    }
    hsk_secp256k1_scratch_reset(scratch);
    points = (hsk_secp256k1_ge *) hsk_secp256k1_scratch_alloc(scratch, entries * sizeof(*points));
    scalars = (hsk_secp256k1_scalar *) hsk_secp256k1_scratch_alloc(scratch, entries * sizeof(*scalars));
    state_space = (struct hsk_secp256k1_pippenger_state *) hsk_secp256k1_scratch_alloc(scratch, sizeof(*state_space));
    state_space->ps = (struct hsk_secp256k1_pippenger_point_state *) hsk_secp256k1_scratch_alloc(scratch, entries * sizeof(*state_space->ps));
    state_space->wnaf_na = (int *) hsk_secp256k1_scratch_alloc(scratch, entries*(WNAF_SIZE(bucket_window+1)) * sizeof(int));
    buckets = (hsk_secp256k1_gej *) hsk_secp256k1_scratch_alloc(scratch, (1<<bucket_window) * sizeof(*buckets));

    if (inp_g_sc != NULL) {
        scalars[0] = *inp_g_sc;
        points[0] = hsk_secp256k1_ge_const_g;
        idx++;
#ifdef HSK_USE_ENDOMORPHISM
        hsk_secp256k1_ecmult_endo_split(&scalars[0], &scalars[1], &points[0], &points[1]);
        idx++;
#endif
    }

    while (point_idx < n_points) {
        if (!cb(&scalars[idx], &points[idx], point_idx + cb_offset, cbdata)) {
            return 0;
        }
        idx++;
#ifdef HSK_USE_ENDOMORPHISM
        hsk_secp256k1_ecmult_endo_split(&scalars[idx - 1], &scalars[idx], &points[idx - 1], &points[idx]);
        idx++;
#endif
        point_idx++;
    }

    hsk_secp256k1_ecmult_pippenger_wnaf(buckets, bucket_window, state_space, r, scalars, points, idx);

    /* Clear data */
    for(i = 0; (size_t)i < idx; i++) {
        hsk_secp256k1_scalar_clear(&scalars[i]);
        state_space->ps[i].skew_na = 0;
        for(j = 0; j < WNAF_SIZE(bucket_window+1); j++) {
            state_space->wnaf_na[i * WNAF_SIZE(bucket_window+1) + j] = 0;
        }
    }
    for(i = 0; i < 1<<bucket_window; i++) {
        hsk_secp256k1_gej_clear(&buckets[i]);
    }
    return 1;
}

/* Wrapper for hsk_secp256k1_ecmult_multi_func interface */
static int hsk_secp256k1_ecmult_pippenger_batch_single(const hsk_secp256k1_ecmult_context *actx, hsk_secp256k1_scratch *scratch, hsk_secp256k1_gej *r, const hsk_secp256k1_scalar *inp_g_sc, hsk_secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n) {
    return hsk_secp256k1_ecmult_pippenger_batch(actx, scratch, r, inp_g_sc, cb, cbdata, n, 0);
}

/**
 * Returns the maximum number of points in addition to G that can be used with
 * a given scratch space. The function ensures that fewer points may also be
 * used.
 */
static size_t hsk_secp256k1_pippenger_max_points(hsk_secp256k1_scratch *scratch) {
    size_t max_alloc = hsk_secp256k1_scratch_max_allocation(scratch, PIPPENGER_SCRATCH_OBJECTS);
    int bucket_window;
    size_t res = 0;

    for (bucket_window = 1; bucket_window <= PIPPENGER_MAX_BUCKET_WINDOW; bucket_window++) {
        size_t n_points;
        size_t max_points = hsk_secp256k1_pippenger_bucket_window_inv(bucket_window);
        size_t space_for_points;
        size_t space_overhead;
        size_t entry_size = sizeof(hsk_secp256k1_ge) + sizeof(hsk_secp256k1_scalar) + sizeof(struct hsk_secp256k1_pippenger_point_state) + (WNAF_SIZE(bucket_window+1)+1)*sizeof(int);

#ifdef HSK_USE_ENDOMORPHISM
        entry_size = 2*entry_size;
#endif
        space_overhead = ((1<<bucket_window) * sizeof(hsk_secp256k1_gej) + entry_size + sizeof(struct hsk_secp256k1_pippenger_state));
        if (space_overhead > max_alloc) {
            break;
        }
        space_for_points = max_alloc - space_overhead;

        n_points = space_for_points/entry_size;
        n_points = n_points > max_points ? max_points : n_points;
        if (n_points > res) {
            res = n_points;
        }
        if (n_points < max_points) {
            /* A larger bucket_window may support even more points. But if we
             * would choose that then the caller couldn't safely use any number
             * smaller than what this function returns */
            break;
        }
    }
    return res;
}

typedef int (*hsk_secp256k1_ecmult_multi_func)(const hsk_secp256k1_ecmult_context*, hsk_secp256k1_scratch*, hsk_secp256k1_gej*, const hsk_secp256k1_scalar*, hsk_secp256k1_ecmult_multi_callback cb, void*, size_t);
static int hsk_secp256k1_ecmult_multi_var(const hsk_secp256k1_ecmult_context *ctx, hsk_secp256k1_scratch *scratch, hsk_secp256k1_gej *r, const hsk_secp256k1_scalar *inp_g_sc, hsk_secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n) {
    size_t i;

    int (*f)(const hsk_secp256k1_ecmult_context*, hsk_secp256k1_scratch*, hsk_secp256k1_gej*, const hsk_secp256k1_scalar*, hsk_secp256k1_ecmult_multi_callback cb, void*, size_t, size_t);
    size_t max_points;
    size_t n_batches;
    size_t n_batch_points;

    hsk_secp256k1_gej_set_infinity(r);
    if (inp_g_sc == NULL && n == 0) {
        return 1;
    } else if (n == 0) {
        hsk_secp256k1_scalar szero;
        hsk_secp256k1_scalar_set_int(&szero, 0);
        hsk_secp256k1_ecmult(ctx, r, r, &szero, inp_g_sc);
        return 1;
    }

    max_points = hsk_secp256k1_pippenger_max_points(scratch);
    if (max_points == 0) {
        return 0;
    } else if (max_points > ECMULT_MAX_POINTS_PER_BATCH) {
        max_points = ECMULT_MAX_POINTS_PER_BATCH;
    }
    n_batches = (n+max_points-1)/max_points;
    n_batch_points = (n+n_batches-1)/n_batches;

    if (n_batch_points >= ECMULT_PIPPENGER_THRESHOLD) {
        f = hsk_secp256k1_ecmult_pippenger_batch;
    } else {
        max_points = hsk_secp256k1_strauss_max_points(scratch);
        if (max_points == 0) {
            return 0;
        }
        n_batches = (n+max_points-1)/max_points;
        n_batch_points = (n+n_batches-1)/n_batches;
        f = hsk_secp256k1_ecmult_strauss_batch;
    }
    for(i = 0; i < n_batches; i++) {
        size_t nbp = n < n_batch_points ? n : n_batch_points;
        size_t offset = n_batch_points*i;
        hsk_secp256k1_gej tmp;
        if (!f(ctx, scratch, &tmp, i == 0 ? inp_g_sc : NULL, cb, cbdata, nbp, offset)) {
            return 0;
        }
        hsk_secp256k1_gej_add_var(r, r, &tmp, NULL);
        n -= nbp;
    }
    return 1;
}

#endif /* HSK_SECP256K1_ECMULT_IMPL_H */
