/*
 *  https://github.com/IAIK/Picnic/blob/master/randomness.c
 *
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "random.h"

#if defined(HAVE_RANDOMBYTES) || defined(SUPERCOP)
extern void randombytes(unsigned char *x, unsigned long long xlen);

bool
hsk_randombytes(uint8_t *dst, size_t len) {
  randombytes(dst, len);
  return true;
}
#else
#if defined(__linux__) \
  && ((defined(HAVE_SYS_RANDOM_H) && defined(HAVE_GETRANDOM)) \
  || (__GLIBC__ > 2 || __GLIBC_MINOR__ >= 25))
#include <sys/random.h>

bool
hsk_randombytes(uint8_t *dst, size_t len) {
  const ssize_t ret = getrandom(dst, len, GRND_NONBLOCK);
  if (ret < 0 || (size_t)ret != len)
    return false;
  return true;
}
#elif defined(__APPLE__) && defined(HAVE_APPLE_FRAMEWORK)
#include <Security/Security.h>

bool
hsk_randombytes(uint8_t *dst, size_t len) {
  if (SecRandomCopyBytes(kSecRandomDefault, len, dst) == errSecSuccess)
    return true;
  return false;
}
#elif defined(__linux__) || defined(__APPLE__)
#include <stdio.h>

bool
hsk_randombytes(uint8_t *dst, size_t len) {
  FILE *urandom = fopen("/dev/urandom", "r");

  if (!urandom)
    return false;

  size_t nbytes = fread(dst, 1, len, urandom);

  fclose(urandom);

  return nbytes == len;
}
#elif defined(_WIN16) || defined(_WIN32) || defined(_WIN64)
#include <windows.h>

bool
hsk_randombytes(uint8_t *dst, size_t len) {
  NTSTATUS r = BCryptGenRandom(NULL, dst, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

  if (!BCRYPT_SUCCESS(r))
    return false;

  return true;
}
#else
#error "Unsupported OS for randomness."
#endif
#endif
