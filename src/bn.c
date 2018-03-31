/**
 * Parts of this software are based on tiny-bignum-c:
 * https://github.com/kokke/tiny-bignum-c
 *
 * tiny-bignum-c resides in the public domain.
 */

#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <stdbool.h>

#include "bn.h"

static void _lshift_one_bit(hsk_bn_t *a);
static void _rshift_one_bit(hsk_bn_t *a);
static void _lshift_word(hsk_bn_t *a, int nwords);
static void _rshift_word(hsk_bn_t *a, int nwords);

void
hsk_bn_init(hsk_bn_t *n) {
  HSK_BN_REQUIRE(n, "n is null");

  int i;
  for (i = 0; i < HSK_BN_ARRAY_SIZE; i++)
    n->array[i] = 0;
}

void
hsk_bn_from_int(hsk_bn_t *n, HSK_BN_DTYPE_TMP i) {
  HSK_BN_REQUIRE(n, "n is null");

  hsk_bn_init(n);

#if (HSK_BN_WORD_SIZE == 1)
  n->array[0] = (i & 0x000000ff);
  n->array[1] = (i & 0x0000ff00) >> 8;
  n->array[2] = (i & 0x00ff0000) >> 16;
  n->array[3] = (i & 0xff000000) >> 24;
#elif (HSK_BN_WORD_SIZE == 2)
  n->array[0] = (i & 0x0000ffff);
  n->array[1] = (i & 0xffff0000) >> 16;
#elif (HSK_BN_WORD_SIZE == 4)
  n->array[0] = i;
  HSK_BN_DTYPE_TMP num_32 = 32;
  HSK_BN_DTYPE_TMP tmp = i >> num_32;
  n->array[1] = tmp;
#endif
}

int
hsk_bn_to_int(hsk_bn_t *n) {
  HSK_BN_REQUIRE(n, "n is null");

  int ret = 0;

  // Endianness issue if machine
  // is not little-endian?
#if (HSK_BN_WORD_SIZE == 1)
  ret += n->array[0];
  ret += n->array[1] << 8;
  ret += n->array[2] << 16;
  ret += n->array[3] << 24;
#elif (HSK_BN_WORD_SIZE == 2)
  ret += n->array[0];
  ret += n->array[1] << 16;
#elif (HSK_BN_WORD_SIZE == 4)
  ret += n->array[0];
#endif

  return ret;
}

void
hsk_bn_from_string(hsk_bn_t *n, char *str, int nbytes) {
  HSK_BN_REQUIRE(n, "n is null");
  HSK_BN_REQUIRE(str, "str is null");
  HSK_BN_REQUIRE(nbytes > 0, "nbytes must be positive");
  HSK_BN_REQUIRE((nbytes & 1) == 0,
    "string format must be in hex -> equal number of bytes");

  hsk_bn_init(n);

  // HSK_BN_DTYPE is defined in bn.h - uint{8,16,32,64}_t
  HSK_BN_DTYPE tmp;

  // index into string
  int i = nbytes - (2 * HSK_BN_WORD_SIZE);

  // index into array
  int j = 0;

  // reading last hex-byte "MSB" from string first -> big endian
  // MSB ~= most significant byte / block ? :)
  while (i >= 0) {
    tmp = 0;

    sscanf(&str[i], HSK_BN_SSCANF_FMT, &tmp);

    n->array[j] = tmp;

    // step HSK_BN_WORD_SIZE hex-byte(s) back in the string.
    i -= (2 * HSK_BN_WORD_SIZE);

    // step one element forward in the array.
    j += 1;
  }
}

void
hsk_bn_to_string(hsk_bn_t *n, char *str, int nbytes) {
  HSK_BN_REQUIRE(n, "n is null");
  HSK_BN_REQUIRE(str, "str is null");
  HSK_BN_REQUIRE(nbytes > 0, "nbytes must be positive");
  HSK_BN_REQUIRE((nbytes & 1) == 0,
    "string format must be in hex -> equal number of bytes");

  // index into array - reading
  // "MSB" first -> big-endian
  int j = HSK_BN_ARRAY_SIZE - 1;

  // index into string representation.
  int i = 0;

  // reading last array-element
  // "MSB" first -> big endian
  while ((j >= 0) && (nbytes > (i + 1))) {
    sprintf(&str[i], HSK_BN_SPRINTF_FMT, n->array[j]);

    // step HSK_BN_WORD_SIZE hex-byte(s)
    // forward in the string.
    i += (2 * HSK_BN_WORD_SIZE);

    // step one element back
    // in the array.
    j -= 1;
  }

  // Count leading zeros:
  j = 0;
  while (str[j] == '0')
    j += 1;

  // Move string j places ahead,
  // effectively skipping leading zeros
  for (i = 0; i < (nbytes - j); i++)
    str[i] = str[i + j];

  // Zero-terminate string
  str[i] = 0;
}

void
hsk_bn_from_array(hsk_bn_t *n, unsigned char *array, size_t size) {
  HSK_BN_REQUIRE(n, "n is null");
  HSK_BN_REQUIRE(array, "array is null");

  hsk_bn_init(n);

  int j = (size / HSK_BN_WORD_SIZE) - 1;
  int i = 0;

  for (; j >= 0; j--) {
#if (HSK_BN_WORD_SIZE == 1)
    n->array[j] = (HSK_BN_DTYPE)array[i++];
#elif (HSK_BN_WORD_SIZE == 2)
    n->array[j] = ((HSK_BN_DTYPE)array[i++]) << 8;
    n->array[j] |= (HSK_BN_DTYPE)array[i++];
#elif (HSK_BN_WORD_SIZE == 4)
    n->array[j] = ((HSK_BN_DTYPE)array[i++]) << 24;
    n->array[j] |= ((HSK_BN_DTYPE)array[i++]) << 16;
    n->array[j] |= ((HSK_BN_DTYPE)array[i++]) << 8;
    n->array[j] |= (HSK_BN_DTYPE)array[i++];
#endif
  }
}

void
hsk_bn_to_array(hsk_bn_t *n, unsigned char *array, size_t size) {
  HSK_BN_REQUIRE(n, "n is null");
  HSK_BN_REQUIRE(array, "array is null");

  int j = (size / HSK_BN_WORD_SIZE) - 1;
  int i = 0;

  for (; j >= 0; j--) {
#if (HSK_BN_WORD_SIZE == 1)
    array[i++] = (unsigned char)n->array[j];
#elif (HSK_BN_WORD_SIZE == 2)
    array[i++] = (unsigned char)(n->array[j] >> 8);
    array[i++] = (unsigned char)n->array[j];
#elif (HSK_BN_WORD_SIZE == 4)
    array[i++] = (unsigned char)(n->array[j] >> 24);
    array[i++] = (unsigned char)(n->array[j] >> 16);
    array[i++] = (unsigned char)(n->array[j] >> 8);
    array[i++] = (unsigned char)n->array[j];
#endif
  }
}

void
hsk_bn_neg(hsk_bn_t *n) {
  HSK_BN_REQUIRE(n, "n is null");

  HSK_BN_DTYPE res;
  HSK_BN_DTYPE_TMP tmp; // copy of n

  int i;
  for (i = 0; i < HSK_BN_ARRAY_SIZE; i++) {
    tmp = n->array[i];
    res = ~tmp;
    n->array[i] = res;
  }
}

void
hsk_bn_dec(hsk_bn_t *n) {
  HSK_BN_REQUIRE(n, "n is null");

  HSK_BN_DTYPE tmp; // copy of n
  HSK_BN_DTYPE res;

  int i;
  for (i = 0; i < HSK_BN_ARRAY_SIZE; i++) {
    tmp = n->array[i];
    res = tmp - 1;
    n->array[i] = res;

    if (!(res > tmp))
      break;
  }
}

void
hsk_bn_inc(hsk_bn_t *n) {
  HSK_BN_REQUIRE(n, "n is null");

  HSK_BN_DTYPE res;
  HSK_BN_DTYPE_TMP tmp; // copy of n

  int i;
  for (i = 0; i < HSK_BN_ARRAY_SIZE; i++) {
    tmp = n->array[i];
    res = tmp + 1;
    n->array[i] = res;

    if (res > tmp)
      break;
  }
}

void
hsk_bn_add(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c) {
  HSK_BN_REQUIRE(a, "a is null");
  HSK_BN_REQUIRE(b, "b is null");
  HSK_BN_REQUIRE(c, "c is null");

  HSK_BN_DTYPE_TMP tmp;
  int carry = 0;

  int i;
  for (i = 0; i < HSK_BN_ARRAY_SIZE; i++) {
    tmp = a->array[i] + b->array[i] + carry;
    carry = (tmp > HSK_BN_MAX_VAL);
    c->array[i] = (tmp & HSK_BN_MAX_VAL);
  }
}

void
hsk_bn_sub(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c) {
  HSK_BN_REQUIRE(a, "a is null");
  HSK_BN_REQUIRE(b, "b is null");
  HSK_BN_REQUIRE(c, "c is null");

  HSK_BN_DTYPE_TMP res;
  HSK_BN_DTYPE_TMP tmp1;
  HSK_BN_DTYPE_TMP tmp2;
  int borrow = 0;

  int i;
  for (i = 0; i < HSK_BN_ARRAY_SIZE; i++) {
    // + number_base
    tmp1 = (HSK_BN_DTYPE_TMP)a->array[i] + (HSK_BN_MAX_VAL + 1);
    tmp2 = (HSK_BN_DTYPE_TMP)b->array[i] + borrow;;
    res = (tmp1 - tmp2);

    // "modulo number_base" == "% (number_base - 1)"
    // if number_base is 2^N
    c->array[i] = (HSK_BN_DTYPE)(res & HSK_BN_MAX_VAL);
    borrow = (res <= HSK_BN_MAX_VAL);
  }
}

void
hsk_bn_mul(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c) {
  HSK_BN_REQUIRE(a, "a is null");
  HSK_BN_REQUIRE(b, "b is null");
  HSK_BN_REQUIRE(c, "c is null");

  hsk_bn_t row;
  hsk_bn_t tmp;
  hsk_bn_t cc;
  int i, j;

  hsk_bn_init(&cc);

  for (i = 0; i < HSK_BN_ARRAY_SIZE; i++) {
    hsk_bn_init(&row);

    for (j = 0; j < HSK_BN_ARRAY_SIZE; j++) {
      if (i + j < HSK_BN_ARRAY_SIZE) {
        hsk_bn_init(&tmp);

        HSK_BN_DTYPE_TMP intermediate =
          ((HSK_BN_DTYPE_TMP)a->array[i] * (HSK_BN_DTYPE_TMP)b->array[j]);

        hsk_bn_from_int(&tmp, intermediate);
        _lshift_word(&tmp, i + j);
        hsk_bn_add(&tmp, &row, &row);
      }
    }

    hsk_bn_add(&cc, &row, &cc);
  }

  hsk_bn_assign(c, &cc);
}

void
hsk_bn_div(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c) {
  HSK_BN_REQUIRE(a, "a is null");
  HSK_BN_REQUIRE(b, "b is null");
  HSK_BN_REQUIRE(c, "c is null");

  hsk_bn_t current;
  hsk_bn_t denom;
  hsk_bn_t tmp;

  // int current = 1;
  hsk_bn_from_int(&current, 1);
  // denom = b
  hsk_bn_assign(&denom, b);
  // tmp = a
  hsk_bn_assign(&tmp, a);

  const HSK_BN_DTYPE_TMP half_max = 1 + (HSK_BN_DTYPE_TMP)(HSK_BN_MAX_VAL / 2);
  bool overflow = false;

  // while (denom <= a) {
  while (hsk_bn_cmp(&denom, a) != 1) {
    if (denom.array[HSK_BN_ARRAY_SIZE - 1] >= half_max) {
      overflow = true;
      break;
    }

    // current <<= 1;
    _lshift_one_bit(&current);

    // denom <<= 1;
    _lshift_one_bit(&denom);
  }

  if (!overflow) {
    // denom >>= 1;
    _rshift_one_bit(&denom);
    // current >>= 1;
    _rshift_one_bit(&current);
  }

  // int answer = 0;
  hsk_bn_init(c);

  // while (current != 0)
  while (!hsk_bn_is_zero(&current)) {
    // if (dividend >= denom)
    if (hsk_bn_cmp(&tmp, &denom) != -1)  {
      // dividend -= denom;
      hsk_bn_sub(&tmp, &denom, &tmp);
      // answer |= current;
      hsk_bn_or(c, &current, c);
    }

    // current >>= 1;
    _rshift_one_bit(&current);

    // denom >>= 1;
    _rshift_one_bit(&denom);
  }

  // return answer;
}

void
hsk_bn_lshift(hsk_bn_t *a, hsk_bn_t *b, int nbits) {
  HSK_BN_REQUIRE(a, "a is null");
  HSK_BN_REQUIRE(b, "b is null");
  HSK_BN_REQUIRE(nbits >= 0, "no negative shifts");

  // Handle shift in multiples of word-size
  const int nbits_pr_word = (HSK_BN_WORD_SIZE * 8);
  int nwords = nbits / nbits_pr_word;

  if (nwords != 0) {
    _lshift_word(a, nwords);
    nbits -= (nwords * nbits_pr_word);
  }

  if (nbits != 0) {
    int i;
    for (i = (HSK_BN_ARRAY_SIZE - 1); i > 0; i--) {
      a->array[i] = (a->array[i] << nbits)
        | (a->array[i - 1] >> ((8 * HSK_BN_WORD_SIZE) - nbits));
    }

    a->array[i] <<= nbits;
  }

  hsk_bn_assign(b, a);
}

void
hsk_bn_rshift(hsk_bn_t *a, hsk_bn_t *b, int nbits) {
  HSK_BN_REQUIRE(a, "a is null");
  HSK_BN_REQUIRE(b, "b is null");
  HSK_BN_REQUIRE(nbits >= 0, "no negative shifts");

  // Handle shift in multiples of word-size
  const int nbits_pr_word = (HSK_BN_WORD_SIZE * 8);
  int nwords = nbits / nbits_pr_word;

  if (nwords != 0) {
    _rshift_word(a, nwords);
    nbits -= (nwords * nbits_pr_word);
  }

  if (nbits != 0) {
    int i;
    for (i = 0; i < (HSK_BN_ARRAY_SIZE - 1); i++) {
      a->array[i] = (a->array[i] >> nbits)
        | (a->array[i + 1] << ((8 * HSK_BN_WORD_SIZE) - nbits));
    }

    a->array[i] >>= nbits;
  }

  hsk_bn_assign(b, a);
}

void
hsk_bn_mod(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c) {
  // mod(a, b) = a - ((a / b) * b)
  // example:
  //   mod(8, 3) = 8 - ((8 / 3) * 3) = 2
  HSK_BN_REQUIRE(a, "a is null");
  HSK_BN_REQUIRE(b, "b is null");
  HSK_BN_REQUIRE(c, "c is null");

  hsk_bn_t tmp;

  // c = (a / b)
  hsk_bn_div(a, b, c);

  // tmp = (c * b)
  hsk_bn_mul(c, b, &tmp);

  // c = a - tmp
  hsk_bn_sub(a, &tmp, c);
}

void
hsk_bn_and(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c) {
  HSK_BN_REQUIRE(a, "a is null");
  HSK_BN_REQUIRE(b, "b is null");
  HSK_BN_REQUIRE(c, "c is null");

  int i;
  for (i = 0; i < HSK_BN_ARRAY_SIZE; i++)
    c->array[i] = (a->array[i] & b->array[i]);
}

void
hsk_bn_or(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c) {
  HSK_BN_REQUIRE(a, "a is null");
  HSK_BN_REQUIRE(b, "b is null");
  HSK_BN_REQUIRE(c, "c is null");

  int i;
  for (i = 0; i < HSK_BN_ARRAY_SIZE; i++)
    c->array[i] = (a->array[i] | b->array[i]);
}

void
hsk_bn_xor(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c) {
  HSK_BN_REQUIRE(a, "a is null");
  HSK_BN_REQUIRE(b, "b is null");
  HSK_BN_REQUIRE(c, "c is null");

  int i;
  for (i = 0; i < HSK_BN_ARRAY_SIZE; i++)
    c->array[i] = (a->array[i] ^ b->array[i]);
}

int
hsk_bn_cmp(hsk_bn_t *a, hsk_bn_t *b) {
  HSK_BN_REQUIRE(a, "a is null");
  HSK_BN_REQUIRE(b, "b is null");

  int i = HSK_BN_ARRAY_SIZE;

  do {
    // Decrement first, to start
    // with last array element
    i -= 1;

    if (a->array[i] > b->array[i])
      return 1;
    else if (a->array[i] < b->array[i])
      return -1;
  } while (i != 0);

  return 0;
}

int
hsk_bn_is_zero(hsk_bn_t *n) {
  HSK_BN_REQUIRE(n, "n is null");

  int i;
  for (i = 0; i < HSK_BN_ARRAY_SIZE; i++) {
    if (n->array[i])
      return 0;
  }

  return 1;
}

void
hsk_bn_pow(hsk_bn_t *a, hsk_bn_t *b, hsk_bn_t *c) {
  HSK_BN_REQUIRE(a, "a is null");
  HSK_BN_REQUIRE(b, "b is null");
  HSK_BN_REQUIRE(c, "c is null");

  hsk_bn_t tmp;
  hsk_bn_t cc;

  hsk_bn_init(&cc);

  if (hsk_bn_cmp(b, &cc) == 0) {
    // Return 1 when exponent
    // is 0 -- n^0 = 1
    hsk_bn_inc(&cc);
  } else {
    // Copy a -> tmp
    hsk_bn_assign(&tmp, a);

    hsk_bn_dec(b);

    // Begin summing products:
    while (!hsk_bn_is_zero(b)) {
      // c = tmp * tmp
      hsk_bn_mul(&tmp, a, &cc);

      // Decrement b by one
      hsk_bn_dec(b);

      hsk_bn_assign(&tmp, &cc);
    }

    // c = tmp
    hsk_bn_assign(&cc, &tmp);
  }

  hsk_bn_assign(c, &cc);
}

void
hsk_bn_assign(hsk_bn_t *dst, hsk_bn_t *src) {
  HSK_BN_REQUIRE(dst, "dst is null");
  HSK_BN_REQUIRE(src, "src is null");

  int i;
  for (i = 0; i < HSK_BN_ARRAY_SIZE; i++)
    dst->array[i] = src->array[i];
}

static void
_rshift_word(hsk_bn_t *a, int nwords) {
  // Naive method:
  HSK_BN_REQUIRE(a, "a is null");
  HSK_BN_REQUIRE(nwords >= 0, "no negative shifts");

  int i;
  for (i = 0; i < nwords; i++)
    a->array[i] = a->array[i + 1];

  for (; i < HSK_BN_ARRAY_SIZE; i++)
    a->array[i] = 0;
}

static void
_lshift_word(hsk_bn_t *a, int nwords) {
  HSK_BN_REQUIRE(a, "a is null");
  HSK_BN_REQUIRE(nwords >= 0, "no negative shifts");

  int i;

  // Shift whole words
  for (i = (HSK_BN_ARRAY_SIZE - 1); i >= nwords; i--)
    a->array[i] = a->array[i - nwords];

  // Zero pad shifted words.
  for (; i >= 0; i--)
    a->array[i] = 0;
}

static void
_lshift_one_bit(hsk_bn_t *a) {
  HSK_BN_REQUIRE(a, "a is null");

  int i;
  for (i = (HSK_BN_ARRAY_SIZE - 1); i > 0; i--) {
    a->array[i] = (a->array[i] << 1)
      | (a->array[i - 1] >> ((8 * HSK_BN_WORD_SIZE) - 1));
  }

  a->array[0] <<= 1;
}

static void
_rshift_one_bit(hsk_bn_t *a) {
  HSK_BN_REQUIRE(a, "a is null");

  int i;
  for (i = 0; i < (HSK_BN_ARRAY_SIZE - 1); i++) {
    a->array[i] = (a->array[i] >> 1)
      | (a->array[i + 1] << ((8 * HSK_BN_WORD_SIZE) - 1));
  }

  a->array[HSK_BN_ARRAY_SIZE - 1] >>= 1;
}
