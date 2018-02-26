#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "uv.h"

// Taken from:
// https://github.com/wahern/dns/blob/master/src/dns.c
#ifndef _HSK_RANDOM
#if defined(HAVE_ARC4RANDOM)  \
  || defined(__OpenBSD__)     \
  || defined(__FreeBSD__)     \
  || defined(__NetBSD__)      \
  || defined(__APPLE__)
#define _HSK_RANDOM arc4random
#elif __linux
#define _HSK_RANDOM random
#else
#define _HSK_RANDOM rand
#endif
#endif

int64_t
hsk_now(void) {
  time_t n = time(NULL);
  assert(n >= 0);
  return (int64_t)n;
}

uint32_t
hsk_random(void) {
  return _HSK_RANDOM();
}

uint64_t
hsk_nonce(void) {
  return (((uint64_t)hsk_random()) << 32) + hsk_random();
}

static inline int32_t
to_nibble(char s) {
  if (s >= '0' && s <= '9')
    return s - '0';

  if (s >= 'A' && s <= 'F')
    return (s - 'A') + 0x0a;

  if (s >= 'a' && s <= 'f')
    return (s - 'a') + 0x0a;

  return -1;
}

static inline char
to_char(uint8_t n) {
  if (n >= 0x00 && n <= 0x09)
    return n + '0';

  if (n >= 0x0a && n <= 0x0f)
    return (n - 0x0a) + 'a';

  return -1;
}

size_t
hsk_hex_encode_size(size_t data_len) {
  return (data_len << 1) + 1;
}

bool
hsk_hex_encode(uint8_t *data, size_t data_len, char *str) {
  if (data == NULL && data_len != 0)
    return false;

  if (str == NULL)
    return false;

  size_t size = data_len << 1;

  int32_t i;
  int32_t p = 0;

  for (i = 0; i < size; i++) {
    char ch;

    if (i & 1) {
      ch = to_char(data[p] & 15);
      p += 1;
    } else {
      ch = to_char(data[p] >> 4);
    }

    if (ch == -1)
      return false;

    str[i] = ch;
  }

  str[i] = '\0';

  return str;
}

char *
hsk_hex_encode32(uint8_t *data) {
  static char str[65];
  assert(hsk_hex_encode(data, 32, str));
  return str;
}

size_t
hsk_hex_decode_size(char *str) {
  if (str == NULL)
    return 0;
  return strlen(str) >> 1;
}

bool
hsk_hex_decode(char *str, uint8_t *data) {
  if (str == NULL)
    return true;

  if (data == NULL)
    return false;

  int32_t i;
  char *s;

  int32_t p = 0;
  uint8_t w;

  for (i = 0, s = str; *s; i++, s++) {
    int32_t n = to_nibble(*s);

    if (n == -1)
      return false;

    if (i & 1) {
      w |= (uint8_t)n;
      data[p] = w;
      p += 1;
    } else {
      w = ((uint8_t)n) << 4;
    }
  }

  if (i & 1)
    return false;

  return true;
}

void
hsk_label_split(char *fqdn, uint8_t *labels, int32_t *count) {
  size_t len = strlen(fqdn);
  bool dot = false;
  int32_t i;
  int32_t j = 0;

  for (i = 0; i < len; i++) {
    if (j == 255)
      break;

    if (dot) {
      if (labels)
        labels[j++] = i;
      dot = false;
      continue;
    }

    if (fqdn[i] == '.') {
      dot = true;
      continue;
    }
  }

  if (count)
    *count = j;
}

int32_t
hsk_label_count(char *fqdn) {
  int32_t count;
  hsk_label_split(fqdn, NULL, &count);
  return count;
}

void
hsk_label_from2(
  char *fqdn,
  uint8_t *labels,
  int32_t count,
  int32_t idx,
  char *ret
) {
  if (idx < 0)
    idx += count;

  if (idx >= count) {
    ret[0] = '\0';
    return;
  }

  size_t start = (size_t)labels[idx];
  size_t end = strlen(fqdn);
  size_t len = end - start;

  memcpy(ret, fqdn + start, len);

  ret[len] = '\0';
}

void
hsk_label_from(char *fqdn, int32_t idx, char *ret) {
  uint8_t labels[255];
  int32_t count;
  hsk_label_split(fqdn, labels, &count);
  hsk_label_from2(fqdn, labels, count, idx, ret);
}

void
hsk_label_get2(
  char *fqdn,
  uint8_t *labels,
  int32_t count,
  int32_t idx,
  char *ret
) {
  if (idx < 0)
    idx += count;

  if (idx >= count) {
    ret[0] = '\0';
    return;
  }

  size_t start = (size_t)labels[idx];
  size_t end;

  if (idx + 1 >= count)
    end = strlen(fqdn);
  else
    end = ((size_t)labels[idx + 1]) - 1;

  size_t len = end - start;

  memcpy(ret, fqdn + start, len);

  ret[len] = '\0';
}

void
hsk_label_get(char *fqdn, int32_t idx, char *ret) {
  uint8_t labels[255];
  int32_t count;
  hsk_label_split(fqdn, labels, &count);
  hsk_label_get2(fqdn, labels, count, idx, ret);
}

bool
hsk_set_inet(
  struct sockaddr *addr,
  int32_t sin_family,
  uint8_t *sin_addr,
  uint16_t sin_port
) {
  if (!addr || !sin_addr)
    return false;

  if (sin_family == AF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)addr;
    sai->sin_family = AF_INET;
    memcpy((void *)&sai->sin_addr, sin_addr, 4);
    if (sin_port)
      sai->sin_port = htons(sin_port);
  } else if (sin_family == AF_INET6) {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)addr;
    sai->sin6_family = AF_INET6;
    memcpy((void *)&sai->sin6_addr, sin_addr, 16);
    if (sin_port)
      sai->sin6_port = htons(sin_port);
  } else {
    return false;
  }

  return true;
}

bool
hsk_get_inet(
  struct sockaddr *addr,
  int32_t *sin_family,
  uint8_t *sin_addr,
  uint16_t *sin_port
) {
  if (!addr || !sin_family || !sin_port)
    return false;

  if (addr->sa_family == AF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)addr;
    *sin_family = AF_INET;
    // *sin_addr = (uint8_t *)&sai->sin_addr;
    memcpy(sin_addr, (void *)&sai->sin_addr, 4);
    if (sin_port)
      *sin_port = ntohs(sai->sin_port);
  } else if (addr->sa_family == AF_INET6) {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)addr;
    *sin_family = AF_INET6;
    // *sin_addr = (uint8_t *)&sai->sin6_addr;
    memcpy(sin_addr, (void *)&sai->sin6_addr, 16);
    if (sin_port)
      *sin_port = ntohs(sai->sin6_port);
  } else {
    return false;
  }

  return true;
}

bool
hsk_inet2string(
  struct sockaddr *src,
  char *dst,
  size_t dst_len,
  uint16_t port
) {
  if (!src || !dst)
    return false;

  void *sin_addr;
  uint16_t sin_port = port;

  if (src->sa_family == AF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)src;
    sin_addr = (void *)&sai->sin_addr;
    if (sai->sin_port)
      sin_port = ntohs(sai->sin_port);
  } else if (src->sa_family == AF_INET6) {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)src;
    sin_addr = (void *)&sai->sin6_addr;
    if (sai->sin6_port)
      sin_port = ntohs(sai->sin6_port);
  } else {
    return false;
  }

  if (uv_inet_ntop(src->sa_family, sin_addr, dst, dst_len) != 0)
    return false;

  if (port) {
    size_t len = strlen(dst);

    if (dst_len - len < 7)
      return false;

    sprintf(dst, "%s@%d", dst, sin_port);
  }

  return true;
}

bool
hsk_string2inet(char *src, struct sockaddr *dst, uint16_t port) {
  if (!src || !dst)
    return false;

  uint16_t sin_port = port;
  char *at = strstr(src, "@");

  if (port && at) {
    int32_t i = 0;
    uint32_t word = 0;
    char *s = at + 1;

    for (; *s; s++) {
      int32_t ch = ((int32_t)*s) - 0x30;

      if (ch < 0 || ch > 9)
        return false;

      if (i == 5)
        return false;

      word *= 10;
      word += ch;

      i += 1;
    }

    sin_port = (uint16_t)word;
    *at = '\0';
  } else if (!port && at) {
    return false;
  }

  bool ret = true;
  uint8_t sin_addr[16];

  if (uv_inet_pton(AF_INET, src, (void *)sin_addr) == 0) {
    struct sockaddr_in *sai = (struct sockaddr_in *)dst;
    sai->sin_family = AF_INET;
    memcpy(&sai->sin_addr, (void *)sin_addr, sizeof(struct in_addr));
    sai->sin_port = htons(sin_port);
  } else if (uv_inet_pton(AF_INET6, src, (void *)sin_addr) == 0) {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)dst;
    sai->sin6_family = AF_INET6;
    memcpy(&sai->sin6_addr, (void *)sin_addr, sizeof(struct in6_addr));
    sai->sin6_port = htons(sin_port);
  } else {
    ret = false;
  }

  if (at)
    *at = '@';

  return ret;
}
