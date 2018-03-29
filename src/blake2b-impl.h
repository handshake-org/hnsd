/**
 * Parts of this software are based on BLAKE2:
 * https://github.com/BLAKE2/BLAKE2
 *
 * BLAKE2 reference source code package - reference C implementations
 *
 * Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under
 * the terms of the CC0, the OpenSSL Licence, or the Apache Public License
 * 2.0, at your option.  The terms of these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - OpenSSL license   : https://www.openssl.org/source/license.html
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * More information about the BLAKE2 hash function can be found at
 * https://blake2.net.
 */

#ifndef _HSK_BLAKE2_IMPL_H
#define _HSK_BLAKE2_IMPL_H

#include <stdint.h>
#include <string.h>

#include "config.h"

#if !defined(__cplusplus) \
  && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
  #if defined(_MSC_VER)
    #define HSK_BLAKE2_INLINE __inline
  #elif defined(__GNUC__)
    #define HSK_BLAKE2_INLINE __inline__
  #else
    #define HSK_BLAKE2_INLINE
  #endif
#else
  #define HSK_BLAKE2_INLINE inline
#endif

static HSK_BLAKE2_INLINE
uint32_t load32(const void *src) {
#ifndef HSK_BIG_ENDIAN
  uint32_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint32_t)(p[0]) <<  0) |
         ((uint32_t)(p[1]) <<  8) |
         ((uint32_t)(p[2]) << 16) |
         ((uint32_t)(p[3]) << 24);
#endif
}

static HSK_BLAKE2_INLINE
uint64_t load64(const void *src) {
#ifndef HSK_BIG_ENDIAN
  uint64_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint64_t)(p[0]) <<  0) |
         ((uint64_t)(p[1]) <<  8) |
         ((uint64_t)(p[2]) << 16) |
         ((uint64_t)(p[3]) << 24) |
         ((uint64_t)(p[4]) << 32) |
         ((uint64_t)(p[5]) << 40) |
         ((uint64_t)(p[6]) << 48) |
         ((uint64_t)(p[7]) << 56);
#endif
}

static HSK_BLAKE2_INLINE
uint16_t load16(const void *src) {
#ifndef HSK_BIG_ENDIAN
  uint16_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint16_t)(p[0]) << 0) |
         ((uint16_t)(p[1]) << 8);
#endif
}

static HSK_BLAKE2_INLINE
void store16(void *dst, uint16_t w) {
#ifndef HSK_BIG_ENDIAN
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = (uint8_t *)dst;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
#endif
}

static HSK_BLAKE2_INLINE
void store32(void *dst, uint32_t w) {
#ifndef HSK_BIG_ENDIAN
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = (uint8_t *)dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
#endif
}

static HSK_BLAKE2_INLINE
void store64(void *dst, uint64_t w) {
#ifndef HSK_BIG_ENDIAN
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = (uint8_t *)dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
  p[4] = (uint8_t)(w >> 32);
  p[5] = (uint8_t)(w >> 40);
  p[6] = (uint8_t)(w >> 48);
  p[7] = (uint8_t)(w >> 56);
#endif
}

static HSK_BLAKE2_INLINE
uint64_t load48(const void *src) {
  const uint8_t *p = (const uint8_t *)src;
  return ((uint64_t)(p[0]) <<  0) |
         ((uint64_t)(p[1]) <<  8) |
         ((uint64_t)(p[2]) << 16) |
         ((uint64_t)(p[3]) << 24) |
         ((uint64_t)(p[4]) << 32) |
         ((uint64_t)(p[5]) << 40);
}

static HSK_BLAKE2_INLINE
void store48(void *dst, uint64_t w) {
  uint8_t *p = (uint8_t *)dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
  p[4] = (uint8_t)(w >> 32);
  p[5] = (uint8_t)(w >> 40);
}

static HSK_BLAKE2_INLINE
uint32_t rotr32(const uint32_t w, const unsigned c) {
  return (w >> c) | (w << (32 - c));
}

static HSK_BLAKE2_INLINE
uint64_t rotr64(const uint64_t w, const unsigned c) {
  return (w >> c) | (w << (64 - c));
}

/* prevents compiler optimizing out memset() */
static HSK_BLAKE2_INLINE
void secure_zero_memory(void *v, size_t n) {
  static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
  memset_v(v, 0, n);
}

#endif
