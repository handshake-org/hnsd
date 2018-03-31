/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef HSK_SECP256K1_GROUP_H
#define HSK_SECP256K1_GROUP_H

#include "num.h"
#include "field.h"

/** A group element of the secp256k1 curve, in affine coordinates. */
typedef struct {
    hsk_secp256k1_fe x;
    hsk_secp256k1_fe y;
    int infinity; /* whether this represents the point at infinity */
} hsk_secp256k1_ge;

#define HSK_SECP256K1_GE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {HSK_SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), HSK_SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), 0}
#define HSK_SECP256K1_GE_CONST_INFINITY {HSK_SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), HSK_SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}

/** A group element of the secp256k1 curve, in jacobian coordinates. */
typedef struct {
    hsk_secp256k1_fe x; /* actual X: x/z^2 */
    hsk_secp256k1_fe y; /* actual Y: y/z^3 */
    hsk_secp256k1_fe z;
    int infinity; /* whether this represents the point at infinity */
} hsk_secp256k1_gej;

#define HSK_SECP256K1_GEJ_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {HSK_SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), HSK_SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), HSK_SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), 0}
#define HSK_SECP256K1_GEJ_CONST_INFINITY {HSK_SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), HSK_SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), HSK_SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}

typedef struct {
    hsk_secp256k1_fe_storage x;
    hsk_secp256k1_fe_storage y;
} hsk_secp256k1_ge_storage;

#define HSK_SECP256K1_GE_STORAGE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {HSK_SECP256K1_FE_STORAGE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), HSK_SECP256K1_FE_STORAGE_CONST((i),(j),(k),(l),(m),(n),(o),(p))}

#define HSK_SECP256K1_GE_STORAGE_CONST_GET(t) HSK_SECP256K1_FE_STORAGE_CONST_GET(t.x), HSK_SECP256K1_FE_STORAGE_CONST_GET(t.y)

/** Set a group element equal to the point with given X and Y coordinates */
static void hsk_secp256k1_ge_set_xy(hsk_secp256k1_ge *r, const hsk_secp256k1_fe *x, const hsk_secp256k1_fe *y);

/** Set a group element (affine) equal to the point with the given X coordinate
 *  and a Y coordinate that is a quadratic residue modulo p. The return value
 *  is true iff a coordinate with the given X coordinate exists.
 */
static int hsk_secp256k1_ge_set_xquad(hsk_secp256k1_ge *r, const hsk_secp256k1_fe *x);

/** Set a group element (affine) equal to the point with the given X coordinate, and given oddness
 *  for Y. Return value indicates whether the result is valid. */
static int hsk_secp256k1_ge_set_xo_var(hsk_secp256k1_ge *r, const hsk_secp256k1_fe *x, int odd);

/** Check whether a group element is the point at infinity. */
static int hsk_secp256k1_ge_is_infinity(const hsk_secp256k1_ge *a);

/** Check whether a group element is valid (i.e., on the curve). */
static int hsk_secp256k1_ge_is_valid_var(const hsk_secp256k1_ge *a);

static void hsk_secp256k1_ge_neg(hsk_secp256k1_ge *r, const hsk_secp256k1_ge *a);

/** Set a group element equal to another which is given in jacobian coordinates */
static void hsk_secp256k1_ge_set_gej(hsk_secp256k1_ge *r, hsk_secp256k1_gej *a);

/** Set a batch of group elements equal to the inputs given in jacobian coordinates */
static void hsk_secp256k1_ge_set_all_gej_var(hsk_secp256k1_ge *r, const hsk_secp256k1_gej *a, size_t len, const hsk_secp256k1_callback *cb);

/** Set a batch of group elements equal to the inputs given in jacobian
 *  coordinates (with known z-ratios). zr must contain the known z-ratios such
 *  that mul(a[i].z, zr[i+1]) == a[i+1].z. zr[0] is ignored. */
static void hsk_secp256k1_ge_set_table_gej_var(hsk_secp256k1_ge *r, const hsk_secp256k1_gej *a, const hsk_secp256k1_fe *zr, size_t len);

/** Bring a batch inputs given in jacobian coordinates (with known z-ratios) to
 *  the same global z "denominator". zr must contain the known z-ratios such
 *  that mul(a[i].z, zr[i+1]) == a[i+1].z. zr[0] is ignored. The x and y
 *  coordinates of the result are stored in r, the common z coordinate is
 *  stored in globalz. */
static void hsk_secp256k1_ge_globalz_set_table_gej(size_t len, hsk_secp256k1_ge *r, hsk_secp256k1_fe *globalz, const hsk_secp256k1_gej *a, const hsk_secp256k1_fe *zr);

/** Set a group element (affine) equal to the point at infinity. */
static void hsk_secp256k1_ge_set_infinity(hsk_secp256k1_ge *r);

/** Set a group element (jacobian) equal to the point at infinity. */
static void hsk_secp256k1_gej_set_infinity(hsk_secp256k1_gej *r);

/** Set a group element (jacobian) equal to another which is given in affine coordinates. */
static void hsk_secp256k1_gej_set_ge(hsk_secp256k1_gej *r, const hsk_secp256k1_ge *a);

/** Compare the X coordinate of a group element (jacobian). */
static int hsk_secp256k1_gej_eq_x_var(const hsk_secp256k1_fe *x, const hsk_secp256k1_gej *a);

/** Set r equal to the inverse of a (i.e., mirrored around the X axis) */
static void hsk_secp256k1_gej_neg(hsk_secp256k1_gej *r, const hsk_secp256k1_gej *a);

/** Check whether a group element is the point at infinity. */
static int hsk_secp256k1_gej_is_infinity(const hsk_secp256k1_gej *a);

/** Check whether a group element's y coordinate is a quadratic residue. */
static int hsk_secp256k1_gej_has_quad_y_var(const hsk_secp256k1_gej *a);

/** Set r equal to the double of a. If rzr is not-NULL, r->z = a->z * *rzr (where infinity means an implicit z = 0).
 * a may not be zero. Constant time. */
static void hsk_secp256k1_gej_double_nonzero(hsk_secp256k1_gej *r, const hsk_secp256k1_gej *a, hsk_secp256k1_fe *rzr);

/** Set r equal to the double of a. If rzr is not-NULL, r->z = a->z * *rzr (where infinity means an implicit z = 0). */
static void hsk_secp256k1_gej_double_var(hsk_secp256k1_gej *r, const hsk_secp256k1_gej *a, hsk_secp256k1_fe *rzr);

/** Set r equal to the sum of a and b. If rzr is non-NULL, r->z = a->z * *rzr (a cannot be infinity in that case). */
static void hsk_secp256k1_gej_add_var(hsk_secp256k1_gej *r, const hsk_secp256k1_gej *a, const hsk_secp256k1_gej *b, hsk_secp256k1_fe *rzr);

/** Set r equal to the sum of a and b (with b given in affine coordinates, and not infinity). */
static void hsk_secp256k1_gej_add_ge(hsk_secp256k1_gej *r, const hsk_secp256k1_gej *a, const hsk_secp256k1_ge *b);

/** Set r equal to the sum of a and b (with b given in affine coordinates). This is more efficient
    than hsk_secp256k1_gej_add_var. It is identical to hsk_secp256k1_gej_add_ge but without constant-time
    guarantee, and b is allowed to be infinity. If rzr is non-NULL, r->z = a->z * *rzr (a cannot be infinity in that case). */
static void hsk_secp256k1_gej_add_ge_var(hsk_secp256k1_gej *r, const hsk_secp256k1_gej *a, const hsk_secp256k1_ge *b, hsk_secp256k1_fe *rzr);

/** Set r equal to the sum of a and b (with the inverse of b's Z coordinate passed as bzinv). */
static void hsk_secp256k1_gej_add_zinv_var(hsk_secp256k1_gej *r, const hsk_secp256k1_gej *a, const hsk_secp256k1_ge *b, const hsk_secp256k1_fe *bzinv);

#ifdef HSK_USE_ENDOMORPHISM
/** Set r to be equal to lambda times a, where lambda is chosen in a way such that this is very fast. */
static void hsk_secp256k1_ge_mul_lambda(hsk_secp256k1_ge *r, const hsk_secp256k1_ge *a);
#endif

/** Clear a hsk_secp256k1_gej to prevent leaking sensitive information. */
static void hsk_secp256k1_gej_clear(hsk_secp256k1_gej *r);

/** Clear a hsk_secp256k1_ge to prevent leaking sensitive information. */
static void hsk_secp256k1_ge_clear(hsk_secp256k1_ge *r);

/** Convert a group element to the storage type. */
static void hsk_secp256k1_ge_to_storage(hsk_secp256k1_ge_storage *r, const hsk_secp256k1_ge *a);

/** Convert a group element back from the storage type. */
static void hsk_secp256k1_ge_from_storage(hsk_secp256k1_ge *r, const hsk_secp256k1_ge_storage *a);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time. */
static void hsk_secp256k1_ge_storage_cmov(hsk_secp256k1_ge_storage *r, const hsk_secp256k1_ge_storage *a, int flag);

/** Rescale a jacobian point by b which must be non-zero. Constant-time. */
static void hsk_secp256k1_gej_rescale(hsk_secp256k1_gej *r, const hsk_secp256k1_fe *b);

#endif /* HSK_SECP256K1_GROUP_H */
