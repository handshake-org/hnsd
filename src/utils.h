#ifndef _HSK_UTILS_H
#define _HSK_UTILS_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

int64_t
hsk_now(void);

uint32_t
hsk_random(void);

uint64_t
hsk_nonce(void);

size_t
hsk_hex_encode_size(size_t);

char *
hsk_hex_encode(uint8_t *, size_t, char *);

char *
hsk_hex_encode32(uint8_t *);

size_t
hsk_hex_decode_size(char *);

bool
hsk_hex_decode(char *, uint8_t *);

void
hsk_label_split(char *fqdn, uint8_t *labels, int32_t *count);

int32_t
hsk_label_count(char *fqdn);

void
hsk_label_from2(
  char *fqdn,
  uint8_t *labels,
  int32_t count,
  int32_t idx,
  char *ret
);

void
hsk_label_from(char *fqdn, int32_t idx, char *ret);

void
hsk_label_get2(
  char *fqdn,
  uint8_t *labels,
  int32_t count,
  int32_t idx,
  char *ret
);

void
hsk_label_get(char *fqdn, int32_t idx, char *ret);

bool
hsk_set_inet(
  struct sockaddr *addr,
  int32_t sin_family,
  uint8_t *sin_addr,
  uint16_t sin_port
);

bool
hsk_get_inet(
  struct sockaddr *addr,
  int32_t *sin_family,
  uint8_t *sin_addr,
  uint16_t *sin_port
);

bool
hsk_inet2string(
  struct sockaddr *src,
  char *dst,
  size_t dst_len,
  uint16_t port
);

bool
hsk_string2inet(char *src, struct sockaddr *dst, uint16_t port);
#endif
