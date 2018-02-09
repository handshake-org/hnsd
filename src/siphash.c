#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "siphash.h"

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define SIPROUND do { \
  v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; \
  v0 = ROTL(v0, 32); \
  v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2; \
  v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0; \
  v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; \
  v2 = ROTL(v2, 32); \
} while (0)

static inline uint64_t
read64(const void *src) {
#ifdef HSK_LITTLE_ENDIAN
  uint64_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint64_t)(p[0]) << 0)
    | ((uint64_t)(p[1]) << 8)
    | ((uint64_t)(p[2]) << 16)
    | ((uint64_t)(p[3]) << 24)
    | ((uint64_t)(p[4]) << 32)
    | ((uint64_t)(p[5]) << 40)
    | ((uint64_t)(p[6]) << 48)
    | ((uint64_t)(p[7]) << 56);
#endif
}

static uint64_t
_siphash(
  const uint8_t *data,
  size_t len,
  const uint8_t *key
) {
  const uint32_t blocks = len >> 3;
  const uint64_t c0 = 0x736f6d6570736575ull;
  const uint64_t c1 = 0x646f72616e646f6dull;
  const uint64_t c2 = 0x6c7967656e657261ull;
  const uint64_t c3 = 0x7465646279746573ull;
  uint64_t f0 = (uint64_t)len << 56;
  const uint64_t f1 = 0xff;
  const uint64_t k0 = read64(key);
  const uint64_t k1 = read64(key + 8);

  uint64_t v0 = k0 ^ c0;
  uint64_t v1 = k1 ^ c1;
  uint64_t v2 = k0 ^ c2;
  uint64_t v3 = k1 ^ c3;

  for (uint32_t i = 0; i < blocks; i++) {
    uint64_t d = read64(data);
    data += 8;
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
  }

  switch (len & 7) {
    case 7:
      f0 |= ((uint64_t)data[6]) << 48;
    case 6:
      f0 |= ((uint64_t)data[5]) << 40;
    case 5:
      f0 |= ((uint64_t)data[4]) << 32;
    case 4:
      f0 |= ((uint64_t)data[3]) << 24;
    case 3:
      f0 |= ((uint64_t)data[2]) << 16;
    case 2:
      f0 |= ((uint64_t)data[1]) << 8;
    case 1:
      f0 |= ((uint64_t)data[0]);
      break;
    case 0:
      break;
  }

  v3 ^= f0;
  SIPROUND;
  SIPROUND;
  v0 ^= f0;
  v2 ^= f1;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  v0 ^= v1;
  v0 ^= v2;
  v0 ^= v3;

  return v0;
}

static uint64_t
_siphash64(const uint64_t num, const uint8_t *key) {
  const uint64_t c0 = 0x736f6d6570736575ull;
  const uint64_t c1 = 0x646f72616e646f6dull;
  const uint64_t c2 = 0x6c7967656e657261ull;
  const uint64_t c3 = 0x7465646279746573ull;
  const uint64_t f0 = num;
  const uint64_t f1 = 0xff;
  const uint64_t k0 = read64(key);
  const uint64_t k1 = read64(key + 8);

  uint64_t v0 = k0 ^ c0;
  uint64_t v1 = k1 ^ c1;
  uint64_t v2 = k0 ^ c2;
  uint64_t v3 = k1 ^ c3;

  v3 ^= f0;
  SIPROUND;
  SIPROUND;
  v0 ^= f0;
  v2 ^= f1;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  v0 ^= v1;
  v0 ^= v2;
  v0 ^= v3;

  return v0;
}

static uint64_t
_siphash64k256(const uint64_t num, const uint8_t *key) {
  const uint64_t f0 = num;
  const uint64_t f1 = 0xff;
  const uint64_t k0 = read64(key);
  const uint64_t k1 = read64(key + 8);
  const uint64_t k2 = read64(key + 16);
  const uint64_t k3 = read64(key + 24);

  uint64_t v0 = k0;
  uint64_t v1 = k1;
  uint64_t v2 = k2;
  uint64_t v3 = k3;

  v3 ^= f0;
  SIPROUND;
  SIPROUND;
  v0 ^= f0;
  v2 ^= f1;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  v0 ^= v1;
  v0 ^= v2;
  v0 ^= v3;

  return v0;
}

uint64_t
hsk_siphash(const uint8_t *data, size_t len, const uint8_t *key) {
  return _siphash(data, len, key);
}

uint32_t
hsk_siphash32(const uint32_t num, const uint8_t *key) {
  return _siphash64((const uint64_t)num, key);
}

uint64_t
hsk_siphash64(const uint64_t num, const uint8_t *key) {
  return _siphash64(num, key);
}

uint32_t
hsk_siphash32k256(const uint32_t num, const uint8_t *key) {
  return _siphash64k256((const uint64_t)num, key);
}

uint64_t
hsk_siphash64k256(const uint64_t num, const uint8_t *key) {
  return _siphash64k256(num, key);
}
