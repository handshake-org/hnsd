/**
 * Parts of this software are based on tiny-bignum-c:
 * https://github.com/kokke/tiny-bignum-c
 *
 * tiny-bignum-c resides in the public domain.
 */

#ifndef _HSK_BN_H
#define _HSK_BN_H

#include <assert.h>
#include <stdint.h>

#define HSK_BN_SIZE (64 / 4)
#define HSK_BN_MSB ((uint64_t)0x80000000)
#define HSK_BN_MAX ((uint64_t)0xffffffff)

typedef struct hsk_bn_s {
  uint32_t array[HSK_BN_SIZE];
} hsk_bn_t;

/*
 * Initialization functions
 */

void
hsk_bn_init(hsk_bn_t *n);

void
hsk_bn_from_int(hsk_bn_t *n, uint64_t i);

uint64_t
hsk_bn_to_int(const hsk_bn_t *n);

void
hsk_bn_from_string(hsk_bn_t *n, const char *str, int nbytes);

void
hsk_bn_to_string(const hsk_bn_t *n, char *str, int maxsize);

void
hsk_bn_from_array(hsk_bn_t *n, const uint8_t *array, size_t size);

void
hsk_bn_to_array(const hsk_bn_t *n, uint8_t *array, size_t size);

/*
 * Basic arithmetic operations
 */

void
hsk_bn_add(const hsk_bn_t *a, const hsk_bn_t *b, hsk_bn_t *c); // c = a + b

void
hsk_bn_sub(const hsk_bn_t *a, const hsk_bn_t *b, hsk_bn_t *c); // c = a - b

void
hsk_bn_mul(const hsk_bn_t *a, const hsk_bn_t *b, hsk_bn_t *c); // c = a * b

void
hsk_bn_div(const hsk_bn_t *a, const hsk_bn_t *b, hsk_bn_t *c); // c = a / b

void
hsk_bn_mod(const hsk_bn_t *a, const hsk_bn_t *b, hsk_bn_t *c); // c = a % b

/*
 * Bitwise operations
 */

void
hsk_bn_and(const hsk_bn_t *a, const hsk_bn_t *b, hsk_bn_t *c); // c = a & b

void
hsk_bn_or(const hsk_bn_t *a, const hsk_bn_t *b, hsk_bn_t *c); // c = a | b

void
hsk_bn_xor(const hsk_bn_t *a, const hsk_bn_t *b, hsk_bn_t *c); // c = a ^ b

void
hsk_bn_lshift(hsk_bn_t *a, hsk_bn_t *b, int nbits); // b = a << nbits

void
hsk_bn_rshift(hsk_bn_t *a, hsk_bn_t *b, int nbits); // b = a >> nbits

/*
 * Special operators and comparison
 */

int
hsk_bn_cmp(const hsk_bn_t *a, const hsk_bn_t *b);

int
hsk_bn_is_zero(const hsk_bn_t *n);

void
hsk_bn_neg(hsk_bn_t *n);

void
hsk_bn_inc(hsk_bn_t *n);

void
hsk_bn_dec(hsk_bn_t *n);

// Calculate a^b -- e.g. 2^10 => 1024
void
hsk_bn_pow(const hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c);

void
hsk_bn_assign(hsk_bn_t *dst, const hsk_bn_t *src);

#endif
