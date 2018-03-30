/**
 * Parts of this software are based on tiny-bignum-c:
 * https://github.com/kokke/tiny-bignum-c
 *
 * tiny-bignum-c resides in the public domain.
 */

#ifndef _HSK_BN_H
#define _HSK_BN_H

#include <stdint.h>
#include <assert.h>

#ifndef HSK_BN_WORD_SIZE
#define HSK_BN_WORD_SIZE 4
#endif

#define HSK_BN_ARRAY_SIZE (128 / HSK_BN_WORD_SIZE)

#ifndef HSK_BN_WORD_SIZE
#error Must define HSK_BN_WORD_SIZE to be 1, 2, 4
#elif (HSK_BN_WORD_SIZE == 1)
#define HSK_BN_DTYPE uint8_t
#define HSK_BN_DTYPE_MSB ((HSK_BN_DTYPE_TMP)(0x80))
#define HSK_BN_DTYPE_TMP uint32_t
#define HSK_BN_SPRINTF_FMT "%.02x"
#define HSK_BN_SSCANF_FMT "%2hhx"
#define HSK_BN_MAX_VAL ((HSK_BN_DTYPE_TMP)0xFF)
#elif (HSK_BN_WORD_SIZE == 2)
#define HSK_BN_DTYPE uint16_t
#define HSK_BN_DTYPE_TMP uint32_t
#define HSK_BN_DTYPE_MSB ((HSK_BN_DTYPE_TMP)(0x8000))
#define HSK_BN_SPRINTF_FMT "%.04x"
#define HSK_BN_SSCANF_FMT "%4hx"
#define HSK_BN_MAX_VAL ((HSK_BN_DTYPE_TMP)0xFFFF)
#elif (HSK_BN_WORD_SIZE == 4)
#define HSK_BN_DTYPE uint32_t
#define HSK_BN_DTYPE_TMP uint64_t
#define HSK_BN_DTYPE_MSB ((HSK_BN_DTYPE_TMP)(0x80000000))
#define HSK_BN_SPRINTF_FMT "%.08x"
#define HSK_BN_SSCANF_FMT "%8x"
#define HSK_BN_MAX_VAL ((HSK_BN_DTYPE_TMP)0xFFFFFFFF)
#endif

#ifndef HSK_BN_DTYPE
#error HSK_BN_DTYPE must be defined to uint8_t, uint16_t uint32_t or whatever
#endif

#define HSK_BN_REQUIRE(p, msg) assert(p && #msg)

typedef struct hsk_bn_s {
  HSK_BN_DTYPE array[HSK_BN_ARRAY_SIZE];
} hsk_bn_t;

/*
 * Initialization functions
 */

void
hsk_bn_init(hsk_bn_t *n);

void
hsk_bn_from_int(hsk_bn_t *n, HSK_BN_DTYPE_TMP i);

int
hsk_bn_to_int(hsk_bn_t *n);

void
hsk_bn_from_string(hsk_bn_t *n, char *str, int nbytes);

void
hsk_bn_to_string(hsk_bn_t *n, char *str, int maxsize);

void
hsk_bn_from_array(hsk_bn_t *n, unsigned char *array, size_t size);

void
hsk_bn_to_array(hsk_bn_t *n, unsigned char *array, size_t size);

/*
 * Basic arithmetic operations
 */

void
hsk_bn_add(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c); // c = a + b

void
hsk_bn_sub(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c); // c = a - b

void
hsk_bn_mul(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c); // c = a * b

void
hsk_bn_div(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c); // c = a / b

void
hsk_bn_mod(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c); // c = a % b

/*
 * Bitwise operations
 */

void
hsk_bn_and(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c); // c = a & b

void
hsk_bn_or(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c); // c = a | b

void
hsk_bn_xor(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c); // c = a ^ b

void
hsk_bn_lshift(hsk_bn_t *a, hsk_bn_t *b, int nbits); // b = a << nbits

void
hsk_bn_rshift(hsk_bn_t *a, hsk_bn_t *b, int nbits); // b = a >> nbits

/*
 * Special operators and comparison
 */

int
hsk_bn_cmp(hsk_bn_t *a, hsk_bn_t *b);

int
hsk_bn_is_zero(hsk_bn_t *n);

void
hsk_bn_neg(hsk_bn_t *n);

void
hsk_bn_inc(hsk_bn_t *n);

void
hsk_bn_dec(hsk_bn_t *n);

// Calculate a^b -- e.g. 2^10 => 1024
void
hsk_bn_pow(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c);

void
hsk_bn_assign(hsk_bn_t *dst, hsk_bn_t *src);

#endif
