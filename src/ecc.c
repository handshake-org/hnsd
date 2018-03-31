/**
 * Parts of this software are based on easy-ecc:
 * https://github.com/esxgx/easy-ecc
 *
 * Copyright (c) 2013, Kenneth MacKay
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.

 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <stdint.h>
#include <string.h>

#include "ecc.h"

#define NUM_ECC_DIGITS (HSK_ECC_BYTES / 8)
#define MAX_TRIES 16

typedef unsigned int uint;

#if defined(__SIZEOF_INT128__) \
  || ((__clang_major__ * 100 + __clang_minor__) >= 302)
#define SUPPORTS_INT128 1
#else
#define SUPPORTS_INT128 0
#endif

#if SUPPORTS_INT128
typedef unsigned __int128 uint128_t;
#else
typedef struct {
  uint64_t m_low;
  uint64_t m_high;
} uint128_t;
#endif

typedef struct ecc_point_s {
  uint64_t x[NUM_ECC_DIGITS];
  uint64_t y[NUM_ECC_DIGITS];
} ecc_point_t;

#define CONCAT1(a, b) a##b
#define CONCAT(a, b) CONCAT1(a, b)

#define CURVE_P_16     \
  {0xFFFFFFFFFFFFFFFF, \
   0xFFFFFFFDFFFFFFFF}

#define CURVE_P_24        \
  {0xFFFFFFFFFFFFFFFFull, \
   0xFFFFFFFFFFFFFFFEull, \
   0xFFFFFFFFFFFFFFFFull}

#define CURVE_P_32        \
  {0xFFFFFFFFFFFFFFFFull, \
   0x00000000FFFFFFFFull, \
   0x0000000000000000ull, \
   0xFFFFFFFF00000001ull}

#define CURVE_P_48     \
  {0x00000000FFFFFFFF, \
   0xFFFFFFFF00000000, \
   0xFFFFFFFFFFFFFFFE, \
   0xFFFFFFFFFFFFFFFF, \
   0xFFFFFFFFFFFFFFFF, \
   0xFFFFFFFFFFFFFFFF}

#define CURVE_B_16     \
  {0xD824993C2CEE5ED3, \
   0xE87579C11079F43D}

#define CURVE_B_24        \
  {0xFEB8DEECC146B9B1ull, \
   0x0FA7E9AB72243049ull, \
   0x64210519E59C80E7ull}

#define CURVE_B_32        \
  {0x3BCE3C3E27D2604Bull, \
   0x651D06B0CC53B0F6ull, \
   0xB3EBBD55769886BCull, \
   0x5AC635D8AA3A93E7ull}

#define CURVE_B_48     \
  {0x2A85C8EDD3EC2AEF, \
   0xC656398D8A2ED19D, \
   0x0314088F5013875A, \
   0x181D9C6EFE814112, \
   0x988E056BE3F82D19, \
   0xB3312FA7E23EE7E4}

#define CURVE_G_16 {    \
  {0x0C28607CA52C5B86,  \
   0x161FF7528B899B2D}, \
  {0xC02DA292DDED7A83,  \
   0xCF5AC8395BAFEB13}}

#define CURVE_G_24 {       \
  {0xF4FF0AFD82FF1012ull,  \
   0x7CBF20EB43A18800ull,  \
   0x188DA80EB03090F6ull}, \
  {0x73F977A11E794811ull,  \
   0x631011ED6B24CDD5ull,  \
   0x07192B95FFC8DA78ull}}

#define CURVE_G_32 {       \
  {0xF4A13945D898C296ull,  \
   0x77037D812DEB33A0ull,  \
   0xF8BCE6E563A440F2ull,  \
   0x6B17D1F2E12C4247ull}, \
  {0xCBB6406837BF51F5ull,  \
   0x2BCE33576B315ECEull,  \
   0x8EE7EB4A7C0F9E16ull,  \
   0x4FE342E2FE1A7F9Bull}}

#define CURVE_G_48 {    \
  {0x3A545E3872760AB7,  \
   0x5502F25DBF55296C,  \
   0x59F741E082542A38,  \
   0x6E1D3B628BA79B98,  \
   0x8EB1C71EF320AD74,  \
   0xAA87CA22BE8B0537}, \
  {0x7A431D7C90EA0E5F,  \
   0x0A60B1CE1D7E819D,  \
   0xE9DA3113B5F0B8C0,  \
   0xF8F41DBD289A147C,  \
   0x5D9E98BF9292DC29,  \
   0x3617DE4A96262C6F}}

#define CURVE_N_16     \
  {0x75A30D1B9038A115, \
   0xFFFFFFFE00000000}

#define CURVE_N_24        \
  {0x146BC9B1B4D22831ull, \
   0xFFFFFFFF99DEF836ull, \
   0xFFFFFFFFFFFFFFFFull}

#define CURVE_N_32        \
  {0xF3B9CAC2FC632551ull, \
   0xBCE6FAADA7179E84ull, \
   0xFFFFFFFFFFFFFFFFull, \
   0xFFFFFFFF00000000ull}

#define CURVE_N_48     \
  {0xECEC196ACCC52973, \
   0x581A0DB248B0A77A, \
   0xC7634D81F4372DDF, \
   0xFFFFFFFFFFFFFFFF, \
   0xFFFFFFFFFFFFFFFF, \
   0xFFFFFFFFFFFFFFFF}

static uint64_t curve_p[NUM_ECC_DIGITS] = CONCAT(CURVE_P_, HSK_ECC_CURVE);
static uint64_t curve_b[NUM_ECC_DIGITS] = CONCAT(CURVE_B_, HSK_ECC_CURVE);
static ecc_point_t curve_g = CONCAT(CURVE_G_, HSK_ECC_CURVE);
static uint64_t curve_n[NUM_ECC_DIGITS] = CONCAT(CURVE_N_, HSK_ECC_CURVE);

#if (defined(_WIN32) || defined(_WIN64))
// Windows

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

static int
get_rand_num(uint64_t *vli) {
  HCRYPTPROV prov;

  int r = (int)CryptAcquireContext(
    &prov,
    NULL,
    NULL,
    PROV_RSA_FULL,
    CRYPT_VERIFYCONTEXT
  );

  if (!r)
    return 0;

  CryptGenRandom(prov, HSK_ECC_BYTES, (BYTE *)vli);
  CryptReleaseContext(prov, 0);

  return 1;
}

#else // _WIN32

// Assume that we are using a POSIX-like
// system with /dev/urandom or /dev/random.
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static int
get_rand_num(uint64_t *vli) {
  int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

  if (fd == -1) {
    fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
    if (fd == -1)
      return 0;
  }

  char *ptr = (char *)vli;
  size_t left = HSK_ECC_BYTES;

  while (left > 0) {
    int bytes = read(fd, ptr, left);

    if (bytes <= 0) {
      close(fd);
      return 0;
    }

    left -= bytes;
    ptr += bytes;
  }

  close(fd);
  return 1;
}

#endif // _WIN32

static void
vli_clear(uint64_t *vli) {
  uint i;
  for (i = 0; i < NUM_ECC_DIGITS; i++)
    vli[i] = 0;
}

// Returns 1 if vli == 0, 0 otherwise.
static int
vli_is_zero(uint64_t *vli) {
  uint i;

  for (i = 0; i < NUM_ECC_DIGITS; i++) {
    if (vli[i])
      return 0;
  }

  return 1;
}

// Returns nonzero if bit bit of vli is set.
static uint64_t
vli_test_bit(uint64_t *vli, uint bit) {
  return (vli[bit / 64] & ((uint64_t)1 << (bit % 64)));
}

// Counts the number of 64-bit "digits" in vli.
static uint
vli_num_digits(uint64_t *vli) {
  int i;

  // Search from the end until we find a
  // non-zero digit. We do it in reverse
  // because we expect that most digits
  // will be nonzero.
  for (i = NUM_ECC_DIGITS - 1; i >= 0 && vli[i] == 0; i--)
    ;

  return (i + 1);
}

// Counts the number of bits required for vli.
static uint
vli_num_bits(uint64_t *vli) {
  uint i;
  uint64_t digit;

  uint num_digits = vli_num_digits(vli);

  if (num_digits == 0)
    return 0;

  digit = vli[num_digits - 1];

  for (i = 0; digit; i++)
    digit >>= 1;

  return ((num_digits - 1) * 64 + i);
}

// Sets dest = src.
static void
vli_set(uint64_t *dest, uint64_t *src) {
  uint i;
  for (i = 0; i < NUM_ECC_DIGITS; i++)
    dest[i] = src[i];
}

// Returns sign of left - right.
static int
vli_cmp(uint64_t *left, uint64_t *right) {
  int i;

  for (i = NUM_ECC_DIGITS - 1; i >= 0; i--) {
    if (left[i] > right[i])
      return 1;
    else if (left[i] < right[i])
      return -1;
  }

  return 0;
}

// Computes result = in << c, returning carry.
// Can modify in place (if result == in). 0 < shift < 64.
static uint64_t
vli_lshift(uint64_t *result, uint64_t *in, uint shift) {
  uint64_t carry = 0;
  uint i;

  for (i = 0; i < NUM_ECC_DIGITS; i++) {
    uint64_t temp = in[i];
    result[i] = (temp << shift) | carry;
    carry = temp >> (64 - shift);
  }

  return carry;
}

// Computes vli = vli >> 1.
static void
vli_rshift1(uint64_t *vli) {
  uint64_t *end = vli;
  uint64_t carry = 0;

  vli += NUM_ECC_DIGITS;

  while (vli-- > end) {
    uint64_t temp = *vli;
    *vli = (temp >> 1) | carry;
    carry = temp << 63;
  }
}

// Computes result = left + right,
// returning carry. Can modify in place.
static uint64_t
vli_add(uint64_t *result, uint64_t *left, uint64_t *right) {
  uint64_t carry = 0;
  uint i;

  for (i = 0; i < NUM_ECC_DIGITS; i++) {
    uint64_t sum = left[i] + right[i] + carry;

    if (sum != left[i])
      carry = (sum < left[i]);

    result[i] = sum;
  }

  return carry;
}

// Computes result = left - right,
// returning borrow. Can modify in place.
static uint64_t
vli_sub(uint64_t *result, uint64_t *left, uint64_t *right) {
  uint64_t borrow = 0;
  uint i;

  for (i = 0; i < NUM_ECC_DIGITS; i++) {
    uint64_t diff = left[i] - right[i] - borrow;

    if (diff != left[i])
      borrow = (diff > left[i]);

    result[i] = diff;
  }

  return borrow;
}

#if SUPPORTS_INT128

// Computes result = left * right.
static void
vli_mult(uint64_t *result, uint64_t *left, uint64_t *right) {
  uint128_t r01 = 0;
  uint64_t r2 = 0;

  uint i, k;

  // Compute each digit of result
  // in sequence, maintaining the carries.
  for (k = 0; k < NUM_ECC_DIGITS * 2 - 1; k++) {
    uint min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);

    for (i = min; i <= k && i < NUM_ECC_DIGITS; i++) {
      uint128_t product = (uint128_t)left[i] * right[k - i];
      r01 += product;
      r2 += (r01 < product);
    }

    result[k] = (uint64_t)r01;
    r01 = (r01 >> 64) | (((uint128_t)r2) << 64);
    r2 = 0;
  }

  result[NUM_ECC_DIGITS * 2 - 1] = (uint64_t)r01;
}

// Computes result = left^2.
static void
vli_sqr(uint64_t *result, uint64_t *left) {
  uint128_t r01 = 0;
  uint64_t r2 = 0;

  uint i, k;
  for (k = 0; k < NUM_ECC_DIGITS * 2 - 1; k++) {
    uint min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);

    for (i = min; i <= k && i <= k - i; i++) {
      uint128_t product = (uint128_t)left[i] * left[k - i];

      if (i < k - i) {
        r2 += product >> 127;
        product *= 2;
      }

      r01 += product;
      r2 += (r01 < product);
    }

    result[k] = (uint64_t)r01;
    r01 = (r01 >> 64) | (((uint128_t)r2) << 64);
    r2 = 0;
  }

  result[NUM_ECC_DIGITS * 2 - 1] = (uint64_t)r01;
}

#else // #if SUPPORTS_INT128

static uint128_t
mul_64_64(uint64_t left, uint64_t right) {
  uint128_t result;

  uint64_t a0 = left & 0xffffffffull;
  uint64_t a1 = left >> 32;
  uint64_t b0 = right & 0xffffffffull;
  uint64_t b1 = right >> 32;

  uint64_t m0 = a0 * b0;
  uint64_t m1 = a0 * b1;
  uint64_t m2 = a1 * b0;
  uint64_t m3 = a1 * b1;

  m2 += (m0 >> 32);
  m2 += m1;

  if (m2 < m1)
    m3 += 0x100000000ull;

  result.m_low = (m0 & 0xffffffffull) | (m2 << 32);
  result.m_high = m3 + (m2 >> 32);

  return result;
}

static uint128_t
add_128_128(uint128_t a, uint128_t b) {
  uint128_t result;
  result.m_low = a.m_low + b.m_low;
  result.m_high = a.m_high + b.m_high + (result.m_low < a.m_low);
  return result;
}

static void
vli_mult(uint64_t *result, uint64_t *left, uint64_t *right) {
  uint128_t r01 = {0, 0};
  uint64_t r2 = 0;

  uint i, k;

  // Compute each digit of result
  // in sequence, maintaining the carries.
  for (k = 0; k < NUM_ECC_DIGITS * 2 - 1; k++) {
    uint min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);

    for (i = min; i <= k && i < NUM_ECC_DIGITS; i++) {
      uint128_t product = mul_64_64(left[i], right[k - i]);
      r01 = add_128_128(r01, product);
      r2 += (r01.m_high < product.m_high);
    }

    result[k] = r01.m_low;
    r01.m_low = r01.m_high;
    r01.m_high = r2;
    r2 = 0;
  }

  result[NUM_ECC_DIGITS * 2 - 1] = r01.m_low;
}

static void
vli_sqr(uint64_t *result, uint64_t *left) {
  uint128_t r01 = {0, 0};
  uint64_t r2 = 0;

  uint i, k;
  for (k = 0; k < NUM_ECC_DIGITS * 2 - 1; k++) {
    uint min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);

    for (i = min; i <= k && i <= k - i; i++) {
      uint128_t product = mul_64_64(left[i], left[k - i]);

      if (i < k - i) {
        r2 += product.m_high >> 63;
        product.m_high = (product.m_high << 1) | (product.m_low >> 63);
        product.m_low <<= 1;
      }

      r01 = add_128_128(r01, product);
      r2 += (r01.m_high < product.m_high);
    }

    result[k] = r01.m_low;
    r01.m_low = r01.m_high;
    r01.m_high = r2;
    r2 = 0;
  }

  result[NUM_ECC_DIGITS * 2 - 1] = r01.m_low;
}

#endif // SUPPORTS_INT128

// Computes result = (left + right) % mod.
// Assumes that left < mod and right < mod,
// result != mod.
static void
vli_mod_add(
  uint64_t *result,
  uint64_t *left,
  uint64_t *right,
  uint64_t *mod
) {
  uint64_t carry = vli_add(result, left, right);
  if (carry || vli_cmp(result, mod) >= 0) {
    // result > mod (result = mod + remainder),
    // so subtract mod to get remainder.
    vli_sub(result, result, mod);
  }
}

// Computes result = (left - right) % mod.
// Assumes that left < mod and right < mod,
// result != mod.
static void
vli_mod_sub(
  uint64_t *result,
  uint64_t *left,
  uint64_t *right,
  uint64_t *mod
) {
  uint64_t borrow = vli_sub(result, left, right);
  if (borrow) {
    // In this case, result == -diff == (max int) - diff.
    //  Since -x % d == d - x, we can get the correct result
    // from result + mod (with overflow).
    vli_add(result, result, mod);
  }
}

#if HSK_ECC_CURVE == HSK_SECP128R1

// Computes result = product % curve_p.
// See algorithm 5 and 6 from
// http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf
static void
vli_mmod_fast(uint64_t *result, uint64_t *product) {
  uint64_t tmp[NUM_ECC_DIGITS];
  int carry;

  vli_set(result, product);

  tmp[0] = product[2];
  tmp[1] = (product[3] & 0x1FFFFFFFFull) | (product[2] << 33);
  carry = vli_add(result, result, tmp);

  tmp[0] = (product[2] >> 31) | (product[3] << 33);
  tmp[1] = (product[3] >> 31)
    | ((product[2] & 0xFFFFFFFF80000000ull) << 2);
  carry += vli_add(result, result, tmp);

  tmp[0] = (product[2] >> 62) | (product[3] << 2);
  tmp[1] = (product[3] >> 62)
    | ((product[2] & 0xC000000000000000ull) >> 29) | (product[3] << 35);
  carry += vli_add(result, result, tmp);

  tmp[0] = (product[3] >> 29);
  tmp[1] = ((product[3] & 0xFFFFFFFFE0000000ull) << 4);
  carry += vli_add(result, result, tmp);

  tmp[0] = (product[3] >> 60);
  tmp[1] = (product[3] & 0xFFFFFFFE00000000ull);
  carry += vli_add(result, result, tmp);

  tmp[0] = 0;
  tmp[1] = ((product[3] & 0xF000000000000000ull) >> 27);
  carry += vli_add(result, result, tmp);

  while (carry || vli_cmp(curve_p, result) != 1)
    carry -= vli_sub(result, result, curve_p);
}

#elif HSK_ECC_CURVE == HSK_SECP192R1

// Computes result = product % curve_p.
// See algorithm 5 and 6 from
// http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf
static void
vli_mmod_fast(uint64_t *result, uint64_t *product) {
  uint64_t tmp[NUM_ECC_DIGITS];
  int carry;

  vli_set(result, product);

  vli_set(tmp, &product[3]);
  carry = vli_add(result, result, tmp);

  tmp[0] = 0;
  tmp[1] = product[3];
  tmp[2] = product[4];
  carry += vli_add(result, result, tmp);

  tmp[0] = tmp[1] = product[5];
  tmp[2] = 0;
  carry += vli_add(result, result, tmp);

  while (carry || vli_cmp(curve_p, result) != 1)
    carry -= vli_sub(result, result, curve_p);
}

#elif HSK_ECC_CURVE == HSK_SECP256R1

// Computes result = product % curve_p
// from http://www.nsa.gov/ia/_files/nist-routines.pdf
static void
vli_mmod_fast(uint64_t *result, uint64_t *product) {
  uint64_t tmp[NUM_ECC_DIGITS];
  int carry;

  // t
  vli_set(result, product);

  // s1
  tmp[0] = 0;
  tmp[1] = product[5] & 0xffffffff00000000ull;
  tmp[2] = product[6];
  tmp[3] = product[7];
  carry = vli_lshift(tmp, tmp, 1);
  carry += vli_add(result, result, tmp);

  // s2
  tmp[1] = product[6] << 32;
  tmp[2] = (product[6] >> 32) | (product[7] << 32);
  tmp[3] = product[7] >> 32;
  carry += vli_lshift(tmp, tmp, 1);
  carry += vli_add(result, result, tmp);

  // s3
  tmp[0] = product[4];
  tmp[1] = product[5] & 0xffffffff;
  tmp[2] = 0;
  tmp[3] = product[7];
  carry += vli_add(result, result, tmp);

  // s4
  tmp[0] = (product[4] >> 32) | (product[5] << 32);
  tmp[1] = (product[5] >> 32) | (product[6] & 0xffffffff00000000ull);
  tmp[2] = product[7];
  tmp[3] = (product[6] >> 32) | (product[4] << 32);
  carry += vli_add(result, result, tmp);

  // d1
  tmp[0] = (product[5] >> 32) | (product[6] << 32);
  tmp[1] = (product[6] >> 32);
  tmp[2] = 0;
  tmp[3] = (product[4] & 0xffffffff) | (product[5] << 32);
  carry -= vli_sub(result, result, tmp);

  // d2
  tmp[0] = product[6];
  tmp[1] = product[7];
  tmp[2] = 0;
  tmp[3] = (product[4] >> 32) | (product[5] & 0xffffffff00000000ull);
  carry -= vli_sub(result, result, tmp);

  // d3
  tmp[0] = (product[6] >> 32) | (product[7] << 32);
  tmp[1] = (product[7] >> 32) | (product[4] << 32);
  tmp[2] = (product[4] >> 32) | (product[5] << 32);
  tmp[3] = (product[6] << 32);
  carry -= vli_sub(result, result, tmp);

  // d4
  tmp[0] = product[7];
  tmp[1] = product[4] & 0xffffffff00000000ull;
  tmp[2] = product[5];
  tmp[3] = product[6] & 0xffffffff00000000ull;
  carry -= vli_sub(result, result, tmp);

  if (carry < 0) {
    do {
      carry += vli_add(result, result, curve_p);
    } while (carry < 0);
  } else {
    while (carry || vli_cmp(curve_p, result) != 1)
      carry -= vli_sub(result, result, curve_p);
  }
}

#elif HSK_ECC_CURVE == HSK_SECP384R1

static void
omega_mult(uint64_t *result, uint64_t *right) {
  uint64_t tmp[NUM_ECC_DIGITS];
  uint64_t carry, diff;

  // Multiply by (2^128 + 2^96 - 2^32 + 1).

  // 1
  vli_set(result, right);

  carry = vli_lshift(tmp, right, 32);

  // 2^96 + 1
  result[1 + NUM_ECC_DIGITS] =
    carry + vli_add(result + 1, result + 1, tmp);

  // 2^128 + 2^96 + 1
  result[2 + NUM_ECC_DIGITS] = vli_add(result + 2, result + 2, right);

  // 2^128 + 2^96 - 2^32 + 1
  carry += vli_sub(result, result, tmp);

  diff = result[NUM_ECC_DIGITS] - carry;

  if (diff > result[NUM_ECC_DIGITS]) {
    // Propagate borrow if necessary.
    uint i;
    for (i = 1 + NUM_ECC_DIGITS; ; i++) {
      result[i] -= 1;
      if (result[i] != (uint64_t)-1)
        break;
    }
  }

  result[NUM_ECC_DIGITS] = diff;
}

// Computes result = product % curve_p
// see PDF "Comparing Elliptic Curve Cryptography and RSA on 8-bit CPUs"
// section "Curve-Specific Optimizations"
static void
vli_mmod_fast(uint64_t *result, uint64_t *product) {
  uint64_t tmp[2 * NUM_ECC_DIGITS];

  while (!vli_is_zero(product + NUM_ECC_DIGITS)) { // While c1 != 0
    uint64_t carry = 0;
    uint i;

    vli_clear(tmp);
    vli_clear(tmp + NUM_ECC_DIGITS);
    omega_mult(tmp, product + NUM_ECC_DIGITS); // tmp = w * c1
    vli_clear(product + NUM_ECC_DIGITS); // p = c0

    // (c1, c0) = c0 + w * c1
    for (i = 0; i < NUM_ECC_DIGITS + 3; i++) {
      uint64_t sum = product[i] + tmp[i] + carry;

      if (sum != product[i])
        carry = (sum < product[i]);

      product[i] = sum;
    }
  }

  while (vli_cmp(product, curve_p) > 0)
    vli_sub(product, product, curve_p);

  vli_set(result, product);
}

#endif

// Computes result = (left * right) % curve_p.
static void
vli_mod_mult_fast(uint64_t *result, uint64_t *left, uint64_t *right) {
  uint64_t product[2 * NUM_ECC_DIGITS];
  vli_mult(product, left, right);
  vli_mmod_fast(result, product);
}

// Computes result = left^2 % curve_p.
static void
vli_mod_sqr_fast(uint64_t *result, uint64_t *left) {
  uint64_t product[2 * NUM_ECC_DIGITS];
  vli_sqr(product, left);
  vli_mmod_fast(result, product);
}

#define EVEN(vli) (!(vli[0] & 1))

// Computes result = (1 / input) % mod. All VLIs are the same size.
// See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
// https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf */
static void
vli_mod_inv(uint64_t *result, uint64_t *input, uint64_t *mod) {
  uint64_t a[NUM_ECC_DIGITS], b[NUM_ECC_DIGITS];
  uint64_t u[NUM_ECC_DIGITS], v[NUM_ECC_DIGITS];
  uint64_t carry;
  int cmp_result;

  if (vli_is_zero(input)) {
    vli_clear(result);
    return;
  }

  vli_set(a, input);
  vli_set(b, mod);
  vli_clear(u);
  u[0] = 1;
  vli_clear(v);

  while ((cmp_result = vli_cmp(a, b)) != 0) {
    carry = 0;

    if (EVEN(a)) {
      vli_rshift1(a);

      if (!EVEN(u))
        carry = vli_add(u, u, mod);

      vli_rshift1(u);

      if (carry)
        u[NUM_ECC_DIGITS - 1] |= 0x8000000000000000ull;
    } else if (EVEN(b)) {
      vli_rshift1(b);

      if (!EVEN(v))
        carry = vli_add(v, v, mod);

      vli_rshift1(v);

      if (carry)
        v[NUM_ECC_DIGITS - 1] |= 0x8000000000000000ull;
    } else if (cmp_result > 0) {
      vli_sub(a, a, b);
      vli_rshift1(a);

      if (vli_cmp(u, v) < 0)
        vli_add(u, u, mod);

      vli_sub(u, u, v);

      if (!EVEN(u))
        carry = vli_add(u, u, mod);

      vli_rshift1(u);

      if (carry)
        u[NUM_ECC_DIGITS - 1] |= 0x8000000000000000ull;
    } else {
      vli_sub(b, b, a);
      vli_rshift1(b);

      if (vli_cmp(v, u) < 0)
        vli_add(v, v, mod);

      vli_sub(v, v, u);

      if (!EVEN(v))
        carry = vli_add(v, v, mod);

      vli_rshift1(v);

      if (carry)
        v[NUM_ECC_DIGITS - 1] |= 0x8000000000000000ull;
    }
  }

  vli_set(result, u);
}

// ------ Point operations ------

// Returns 1 if p_point is the point at infinity, 0 otherwise.
static int
ecc_point_is_zero(ecc_point_t *point) {
  return (vli_is_zero(point->x) && vli_is_zero(point->y));
}

// Point multiplication algorithm using
// Montgomery's ladder with co-Z coordinates.
// From http://eprint.iacr.org/2011/338.pdf

// Double in place
static void
ecc_point_double_jacobian(uint64_t *X1, uint64_t *Y1, uint64_t *Z1) {
  // t1 = X, t2 = Y, t3 = Z
  uint64_t t4[NUM_ECC_DIGITS];
  uint64_t t5[NUM_ECC_DIGITS];

  if (vli_is_zero(Z1))
    return;

  vli_mod_sqr_fast(t4, Y1); // t4 = y1^2
  vli_mod_mult_fast(t5, X1, t4); // t5 = x1*y1^2 = A
  vli_mod_sqr_fast(t4, t4); // t4 = y1^4
  vli_mod_mult_fast(Y1, Y1, Z1); // t2 = y1*z1 = z3
  vli_mod_sqr_fast(Z1, Z1); // t3 = z1^2

  vli_mod_add(X1, X1, Z1, curve_p); // t1 = x1 + z1^2
  vli_mod_add(Z1, Z1, Z1, curve_p); // t3 = 2*z1^2
  vli_mod_sub(Z1, X1, Z1, curve_p); // t3 = x1 - z1^2
  vli_mod_mult_fast(X1, X1, Z1); // t1 = x1^2 - z1^4

  vli_mod_add(Z1, X1, X1, curve_p); // t3 = 2*(x1^2 - z1^4)
  vli_mod_add(X1, X1, Z1, curve_p); // t1 = 3*(x1^2 - z1^4)

  if (vli_test_bit(X1, 0)) {
    uint64_t carry = vli_add(X1, X1, curve_p);
    vli_rshift1(X1);
    X1[NUM_ECC_DIGITS - 1] |= carry << 63;
  } else {
    vli_rshift1(X1);
  }

  // t1 = 3/2*(x1^2 - z1^4) = B

  vli_mod_sqr_fast(Z1, X1); // t3 = B^2
  vli_mod_sub(Z1, Z1, t5, curve_p); // t3 = B^2 - A
  vli_mod_sub(Z1, Z1, t5, curve_p); // t3 = B^2 - 2A = x3
  vli_mod_sub(t5, t5, Z1, curve_p); // t5 = A - x3
  vli_mod_mult_fast(X1, X1, t5); // t1 = B * (A - x3)
  vli_mod_sub(t4, X1, t4, curve_p); // t4 = B * (A - x3) - y1^4 = y3

  vli_set(X1, Z1);
  vli_set(Z1, Y1);
  vli_set(Y1, t4);
}

// Modify (x1, y1) => (x1 * z^2, y1 * z^3)
static void
apply_z(uint64_t *X1, uint64_t *Y1, uint64_t *Z) {
  uint64_t t1[NUM_ECC_DIGITS];

  vli_mod_sqr_fast(t1, Z);  // z^2
  vli_mod_mult_fast(X1, X1, t1); // x1 * z^2
  vli_mod_mult_fast(t1, t1, Z);  // z^3
  vli_mod_mult_fast(Y1, Y1, t1); // y1 * z^3
}

// P = (x1, y1) => 2P, (x2, y2) => P'
static void
xycz_initial_double(
  uint64_t *X1,
  uint64_t *Y1,
  uint64_t *X2,
  uint64_t *Y2,
  uint64_t *initial_z
) {
  uint64_t z[NUM_ECC_DIGITS];

  vli_set(X2, X1);
  vli_set(Y2, Y1);

  vli_clear(z);
  z[0] = 1;

  if (initial_z)
    vli_set(z, initial_z);

  apply_z(X1, Y1, z);

  ecc_point_double_jacobian(X1, Y1, z);

  apply_z(X2, Y2, z);
}

// Input P = (x1, y1, Z), Q = (x2, y2, Z)
// Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
// or P => P', Q => P + Q
static void
xycz_add(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2) {
  // t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
  uint64_t t5[NUM_ECC_DIGITS];

  vli_mod_sub(t5, X2, X1, curve_p); // t5 = x2 - x1
  vli_mod_sqr_fast(t5, t5); // t5 = (x2 - x1)^2 = A
  vli_mod_mult_fast(X1, X1, t5);  // t1 = x1*A = B
  vli_mod_mult_fast(X2, X2, t5);  // t3 = x2*A = C
  vli_mod_sub(Y2, Y2, Y1, curve_p); // t4 = y2 - y1
  vli_mod_sqr_fast(t5, Y2); // t5 = (y2 - y1)^2 = D

  vli_mod_sub(t5, t5, X1, curve_p); // t5 = D - B
  vli_mod_sub(t5, t5, X2, curve_p); // t5 = D - B - C = x3
  vli_mod_sub(X2, X2, X1, curve_p); // t3 = C - B
  vli_mod_mult_fast(Y1, Y1, X2); // t2 = y1*(C - B)
  vli_mod_sub(X2, X1, t5, curve_p); // t3 = B - x3
  vli_mod_mult_fast(Y2, Y2, X2); // t4 = (y2 - y1)*(B - x3)
  vli_mod_sub(Y2, Y2, Y1, curve_p); // t4 = y3

  vli_set(X2, t5);
}

// Input P = (x1, y1, Z), Q = (x2, y2, Z)
// Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
// or P => P - Q, Q => P + Q
static void
xycz_addc(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2) {
  // t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
  uint64_t t5[NUM_ECC_DIGITS];
  uint64_t t6[NUM_ECC_DIGITS];
  uint64_t t7[NUM_ECC_DIGITS];

  vli_mod_sub(t5, X2, X1, curve_p); // t5 = x2 - x1
  vli_mod_sqr_fast(t5, t5); // t5 = (x2 - x1)^2 = A
  vli_mod_mult_fast(X1, X1, t5); // t1 = x1*A = B
  vli_mod_mult_fast(X2, X2, t5); // t3 = x2*A = C
  vli_mod_add(t5, Y2, Y1, curve_p); // t4 = y2 + y1
  vli_mod_sub(Y2, Y2, Y1, curve_p); // t4 = y2 - y1

  vli_mod_sub(t6, X2, X1, curve_p); // t6 = C - B
  vli_mod_mult_fast(Y1, Y1, t6); // t2 = y1 * (C - B)
  vli_mod_add(t6, X1, X2, curve_p); // t6 = B + C
  vli_mod_sqr_fast(X2, Y2); // t3 = (y2 - y1)^2
  vli_mod_sub(X2, X2, t6, curve_p); // t3 = x3

  vli_mod_sub(t7, X1, X2, curve_p); // t7 = B - x3
  vli_mod_mult_fast(Y2, Y2, t7); // t4 = (y2 - y1)*(B - x3)
  vli_mod_sub(Y2, Y2, Y1, curve_p); // t4 = y3

  vli_mod_sqr_fast(t7, t5); // t7 = (y2 + y1)^2 = F
  vli_mod_sub(t7, t7, t6, curve_p); // t7 = x3'
  vli_mod_sub(t6, t7, X1, curve_p); // t6 = x3' - B
  vli_mod_mult_fast(t6, t6, t5); // t6 = (y2 + y1)*(x3' - B)
  vli_mod_sub(Y1, t6, Y1, curve_p); // t2 = y3'

  vli_set(X1, t7);
}

static void
ecc_point_mult(
  ecc_point_t *result,
  ecc_point_t *point,
  uint64_t *scalar,
  uint64_t *initial_z
) {
  // R0 and R1
  uint64_t Rx[2][NUM_ECC_DIGITS];
  uint64_t Ry[2][NUM_ECC_DIGITS];
  uint64_t z[NUM_ECC_DIGITS];

  int i, nb;

  vli_set(Rx[1], point->x);
  vli_set(Ry[1], point->y);

  xycz_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], initial_z);

  for (i = vli_num_bits(scalar) - 2; i > 0; i--) {
    nb = !vli_test_bit(scalar, i);
    xycz_addc(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
    xycz_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
  }

  nb = !vli_test_bit(scalar, 0);
  xycz_addc(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);

  // Find final 1/Z value.
  vli_mod_sub(z, Rx[1], Rx[0], curve_p); // X1 - X0
  vli_mod_mult_fast(z, z, Ry[1 - nb]); // Yb * (X1 - X0)
  vli_mod_mult_fast(z, z, point->x); // xP * Yb * (X1 - X0)
  vli_mod_inv(z, z, curve_p); // 1 / (xP * Yb * (X1 - X0))
  vli_mod_mult_fast(z, z, point->y); // yP / (xP * Yb * (X1 - X0))
  vli_mod_mult_fast(z, z, Rx[1 - nb]); // Xb * yP / (xP * Yb * (X1 - X0))

  // End 1/Z calculation

  xycz_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);

  apply_z(Rx[0], Ry[0], z);

  vli_set(result->x, Rx[0]);
  vli_set(result->y, Ry[0]);
}

static void
ecc_bytes2native(
  uint64_t native[NUM_ECC_DIGITS],
  const uint8_t bytes[HSK_ECC_BYTES]
) {
  unsigned i;

  for (i = 0; i < NUM_ECC_DIGITS; i++) {
    const uint8_t *digit = bytes + 8 * (NUM_ECC_DIGITS - 1 - i);

    native[i] = ((uint64_t)digit[0] << 56)
      | ((uint64_t)digit[1] << 48)
      | ((uint64_t)digit[2] << 40)
      | ((uint64_t)digit[3] << 32)
      | ((uint64_t)digit[4] << 24)
      | ((uint64_t)digit[5] << 16)
      | ((uint64_t)digit[6] << 8)
      | (uint64_t)digit[7];
  }
}

static void
ecc_native2bytes(
  uint8_t bytes[HSK_ECC_BYTES],
  const uint64_t native[NUM_ECC_DIGITS]
) {
  unsigned i;
  for (i = 0; i < NUM_ECC_DIGITS; i++) {
    uint8_t *digit = bytes + 8 * (NUM_ECC_DIGITS - 1 - i);
    digit[0] = native[i] >> 56;
    digit[1] = native[i] >> 48;
    digit[2] = native[i] >> 40;
    digit[3] = native[i] >> 32;
    digit[4] = native[i] >> 24;
    digit[5] = native[i] >> 16;
    digit[6] = native[i] >> 8;
    digit[7] = native[i];
  }
}

// Compute a = sqrt(a) (mod curve_p).
static void
mod_sqrt(uint64_t a[NUM_ECC_DIGITS]) {
  unsigned i;
  uint64_t p1[NUM_ECC_DIGITS] = {1};
  uint64_t result[NUM_ECC_DIGITS] = {1};

  // Since curve_p == 3 (mod 4) for all supported curves, we can
  // compute sqrt(a) = a^((curve_p + 1) / 4) (mod curve_p). */

  vli_add(p1, curve_p, p1); // p1 = curve_p + 1

  for (i = vli_num_bits(p1) - 1; i > 1; i--) {
    vli_mod_sqr_fast(result, result);
    if (vli_test_bit(p1, i))
      vli_mod_mult_fast(result, result, a);
  }

  vli_set(a, result);
}

static void
ecc_point_decompress(
  ecc_point_t *point,
  const uint8_t compressed[HSK_ECC_BYTES + 1]
) {
  uint64_t _3[NUM_ECC_DIGITS] = {3}; // -a = 3
  ecc_bytes2native(point->x, compressed + 1);

  vli_mod_sqr_fast(point->y, point->x); // y = x^2
  vli_mod_sub(point->y, point->y, _3, curve_p); // y = x^2 - 3
  vli_mod_mult_fast(point->y, point->y, point->x); // y = x^3 - 3x
  vli_mod_add(point->y, point->y, curve_b, curve_p); // y = x^3 - 3x + b

  mod_sqrt(point->y);

  if ((point->y[0] & 0x01) != (compressed[0] & 0x01))
    vli_sub(point->y, curve_p, point->y);
}

int
hsk_ecc_make_key(
  uint8_t public_key[HSK_ECC_BYTES + 1],
  uint8_t private_key[HSK_ECC_BYTES]
) {
  uint64_t private[NUM_ECC_DIGITS];
  ecc_point_t public;
  unsigned tries = 0;

  do {
    if (!get_rand_num(private) || (tries++ >= MAX_TRIES))
      return 0;

    if (vli_is_zero(private))
      continue;

    // Make sure the private key is in the range [1, n-1].
    // For the supported curves, n is always large enough
    // that we only need to subtract once at most.
    if (vli_cmp(curve_n, private) != 1)
      vli_sub(private, private, curve_n);

    ecc_point_mult(&public, &curve_g, private, NULL);
  } while (ecc_point_is_zero(&public));

  ecc_native2bytes(private_key, private);
  ecc_native2bytes(public_key + 1, public.x);
  public_key[0] = 2 + (public.y[0] & 0x01);

  return 1;
}

int
hsk_ecc_make_pubkey(
  uint8_t private_key[HSK_ECC_BYTES],
  uint8_t public_key[HSK_ECC_BYTES * 2]
) {
  uint64_t private[NUM_ECC_DIGITS];
  ecc_point_t public;

  ecc_bytes2native(private, private_key);

  if (vli_is_zero(private))
    return 0;

  if (vli_cmp(curve_n, private) != 1)
    vli_sub(private, private, curve_n);

  ecc_point_mult(&public, &curve_g, private, NULL);

  if (ecc_point_is_zero(&public))
    return 0;

  ecc_native2bytes(&public_key[0], public.x);
  ecc_native2bytes(&public_key[HSK_ECC_BYTES], public.y);

  return 1;
}

int
hsk_ecc_make_pubkey_compressed(
  uint8_t private_key[HSK_ECC_BYTES],
  uint8_t public_key[HSK_ECC_BYTES + 1]
) {
  uint64_t private[NUM_ECC_DIGITS];
  ecc_point_t public;

  ecc_bytes2native(private, private_key);

  if (vli_is_zero(private))
    return 0;

  if (vli_cmp(curve_n, private) != 1)
    vli_sub(private, private, curve_n);

  ecc_point_mult(&public, &curve_g, private, NULL);

  if (ecc_point_is_zero(&public))
    return 0;

  ecc_native2bytes(public_key + 1, public.x);
  public_key[0] = 2 + (public.y[0] & 0x01);

  return 1;
}

int
hsk_ecc_ecdh(
  const uint8_t public_key[HSK_ECC_BYTES + 1],
  const uint8_t private_key[HSK_ECC_BYTES],
  uint8_t secret[HSK_ECC_BYTES]
) {
  ecc_point_t public;
  uint64_t private[NUM_ECC_DIGITS];
  uint64_t random[NUM_ECC_DIGITS];

  if (!get_rand_num(random))
    return 0;

  ecc_point_decompress(&public, public_key);
  ecc_bytes2native(private, private_key);

  ecc_point_t product;
  ecc_point_mult(&product, &public, private, random);

  ecc_native2bytes(secret, product.x);

  return !ecc_point_is_zero(&product);
}

/*
 * -------- ECDSA code --------
 */

// Computes result = (left * right) % mod.
static void
vli_mod_mult(
  uint64_t *result,
  uint64_t *left,
  uint64_t *right,
  uint64_t *mod
) {
  uint64_t product[2 * NUM_ECC_DIGITS];
  uint64_t mod_multiple[2 * NUM_ECC_DIGITS];
  uint digit_shift, bit_shift;
  uint product_bits;
  uint mod_bits = vli_num_bits(mod);

  vli_mult(product, left, right);

  product_bits = vli_num_bits(product + NUM_ECC_DIGITS);

  if (product_bits)
    product_bits += NUM_ECC_DIGITS * 64;
  else
    product_bits = vli_num_bits(product);

  if (product_bits < mod_bits) {
    // product < mod.
    vli_set(result, product);
    return;
  }

  // Shift mod by (left_bits - mod_bits).
  // This multiplies mod by the largest power
  // of two possible while still resulting in
  // a number less than left.
  vli_clear(mod_multiple);
  vli_clear(mod_multiple + NUM_ECC_DIGITS);
  digit_shift = (product_bits - mod_bits) / 64;
  bit_shift = (product_bits - mod_bits) % 64;

  if (bit_shift) {
    mod_multiple[digit_shift + NUM_ECC_DIGITS] =
      vli_lshift(mod_multiple + digit_shift, mod, bit_shift);
  } else {
    vli_set(mod_multiple + digit_shift, mod);
  }

  // Subtract all multiples of mod to get the remainder.
  vli_clear(result);

  // Use result as a temp var to store 1 (for subtraction)
  result[0] = 1;

  while (product_bits > NUM_ECC_DIGITS * 64
         || vli_cmp(mod_multiple, mod) >= 0) {
    int cmp = vli_cmp(mod_multiple + NUM_ECC_DIGITS,
                        product + NUM_ECC_DIGITS);

    if (cmp < 0 || (cmp == 0 && vli_cmp(mod_multiple, product) <= 0)) {
      if (vli_sub(product, product, mod_multiple)) {
        // borrow
        vli_sub(product + NUM_ECC_DIGITS,
                product + NUM_ECC_DIGITS, result);
      }

      vli_sub(product + NUM_ECC_DIGITS,
              product + NUM_ECC_DIGITS,
              mod_multiple + NUM_ECC_DIGITS);
    }

    uint64_t carry = (mod_multiple[NUM_ECC_DIGITS] & 0x01) << 63;

    vli_rshift1(mod_multiple + NUM_ECC_DIGITS);
    vli_rshift1(mod_multiple);

    mod_multiple[NUM_ECC_DIGITS - 1] |= carry;

    product_bits -= 1;
  }

  vli_set(result, product);
}

static uint
umax(uint a, uint b) {
  return (a > b ? a : b);
}

int
hsk_ecc_sign(
  const uint8_t private_key[HSK_ECC_BYTES],
  const uint8_t hash[HSK_ECC_BYTES],
  uint8_t signature[HSK_ECC_BYTES * 2]
) {
  uint64_t k[NUM_ECC_DIGITS];
  uint64_t tmp[NUM_ECC_DIGITS];
  uint64_t s[NUM_ECC_DIGITS];
  ecc_point_t p;
  unsigned tries = 0;

  do {
    if (!get_rand_num(k) || (tries++ >= MAX_TRIES))
      return 0;

    if (vli_is_zero(k))
      continue;

    if (vli_cmp(curve_n, k) != 1)
      vli_sub(k, k, curve_n);

    // tmp = k * G
    ecc_point_mult(&p, &curve_g, k, NULL);

    // r = x1 (mod n)
    if (vli_cmp(curve_n, p.x) != 1)
      vli_sub(p.x, p.x, curve_n);
  } while (vli_is_zero(p.x));

  ecc_native2bytes(signature, p.x);

  ecc_bytes2native(tmp, private_key);
  vli_mod_mult(s, p.x, tmp, curve_n); // s = r*d
  ecc_bytes2native(tmp, hash);
  vli_mod_add(s, tmp, s, curve_n); // s = e + r*d
  vli_mod_inv(k, k, curve_n); // k = 1 / k
  vli_mod_mult(s, s, k, curve_n); // s = (e + r*d) / k
  ecc_native2bytes(signature + HSK_ECC_BYTES, s);

  return 1;
}

int
hsk_ecc_verify(
  const uint8_t public_key[HSK_ECC_BYTES + 1],
  const uint8_t hash[HSK_ECC_BYTES],
  const uint8_t signature[HSK_ECC_BYTES * 2]
) {
  uint64_t u1[NUM_ECC_DIGITS], u2[NUM_ECC_DIGITS];
  uint64_t z[NUM_ECC_DIGITS];
  ecc_point_t public, sum;
  uint64_t rx[NUM_ECC_DIGITS];
  uint64_t ry[NUM_ECC_DIGITS];
  uint64_t tx[NUM_ECC_DIGITS];
  uint64_t ty[NUM_ECC_DIGITS];
  uint64_t tz[NUM_ECC_DIGITS];

  uint64_t r[NUM_ECC_DIGITS], s[NUM_ECC_DIGITS];

  ecc_point_decompress(&public, public_key);
  ecc_bytes2native(r, signature);
  ecc_bytes2native(s, signature + HSK_ECC_BYTES);

  // r, s must not be 0.
  if (vli_is_zero(r) || vli_is_zero(s))
    return 0;

  // r, s must be < n.
  if (vli_cmp(curve_n, r) != 1 || vli_cmp(curve_n, s) != 1)
    return 0;

  // Calculate u1 and u2.
  vli_mod_inv(z, s, curve_n); // Z = s^-1
  ecc_bytes2native(u1, hash);
  vli_mod_mult(u1, u1, z, curve_n); // u1 = e/s
  vli_mod_mult(u2, r, z, curve_n); // u2 = r/s

  // Calculate sum = G + Q.
  vli_set(sum.x, public.x);
  vli_set(sum.y, public.y);
  vli_set(tx, curve_g.x);
  vli_set(ty, curve_g.y);
  vli_mod_sub(z, sum.x, tx, curve_p); // Z = x2 - x1
  xycz_add(tx, ty, sum.x, sum.y);
  vli_mod_inv(z, z, curve_p); // Z = 1/Z
  apply_z(sum.x, sum.y, z);

  // Use Shamir's trick to calculate u1*G + u2*Q
  ecc_point_t *points[4] = {NULL, &curve_g, &public, &sum};
  uint num_bits = umax(vli_num_bits(u1), vli_num_bits(u2));

  ecc_point_t *point = points[(!!vli_test_bit(u1, num_bits - 1))
    | ((!!vli_test_bit(u2, num_bits - 1)) << 1)];

  vli_set(rx, point->x);
  vli_set(ry, point->y);
  vli_clear(z);
  z[0] = 1;

  int i;
  for (i = num_bits - 2; i >= 0; i--) {
    ecc_point_double_jacobian(rx, ry, z);

    int index = (!!vli_test_bit(u1, i)) | ((!!vli_test_bit(u2, i)) << 1);
    ecc_point_t *point = points[index];

    if (point) {
      vli_set(tx, point->x);
      vli_set(ty, point->y);
      apply_z(tx, ty, z);
      vli_mod_sub(tz, rx, tx, curve_p); // Z = x2 - x1
      xycz_add(tx, ty, rx, ry);
      vli_mod_mult_fast(z, z, tz);
    }
  }

  vli_mod_inv(z, z, curve_p); // Z = 1/Z
  apply_z(rx, ry, z);

  // v = x1 (mod n)
  if (vli_cmp(curve_n, rx) != 1)
    vli_sub(rx, rx, curve_n);

  // Accept only if v == r.
  return (vli_cmp(rx, r) == 0);
}
