#ifndef _HSK_ADDR_H
#define _HSK_ADDR_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// INET6_ADDRSTRLEN = 65
// 65 + 5 + 1 + 2 = 73 - long enough for [ipv6]:port
// 73 + 53  + 1 = 127 - long enough for pubkey@[ipv6]:port
#define HSK_MAX_HOST 128

typedef struct hsk_addr_s {
  uint8_t type;
  uint8_t ip[36];
  uint16_t port;
  uint8_t key[33];
} hsk_addr_t;

typedef struct {
  uint64_t time;
  uint64_t services;
  hsk_addr_t addr;
} hsk_netaddr_t;

void
hsk_addr_init(hsk_addr_t *addr);

hsk_addr_t *
hsk_addr_alloc(void);

hsk_addr_t *
hsk_addr_clone(const hsk_addr_t *other);

void
hsk_addr_copy(hsk_addr_t *addr, const hsk_addr_t *other);

bool
hsk_addr_is_mapped(const hsk_addr_t *addr);

bool
hsk_addr_is_ip4(const hsk_addr_t *addr);

bool
hsk_addr_is_ip6(const hsk_addr_t *addr);

bool
hsk_addr_is_onion(const hsk_addr_t *addr);

bool
hsk_addr_has_key(const hsk_addr_t *addr);

uint16_t
hsk_addr_get_af(const hsk_addr_t *addr);

uint8_t
hsk_addr_get_type(const hsk_addr_t *addr);

bool
hsk_addr_set_type(hsk_addr_t *addr, uint8_t type);

const uint8_t *
hsk_addr_get_ip(const hsk_addr_t *addr);

bool
hsk_addr_set_ip(hsk_addr_t *addr, uint16_t af, const uint8_t *ip);

uint16_t
hsk_addr_get_port(const hsk_addr_t *addr);

bool
hsk_addr_set_port(hsk_addr_t *addr, uint16_t port);

bool
hsk_addr_from_na(hsk_addr_t *addr, const hsk_netaddr_t *na);

bool
hsk_addr_to_na(const hsk_addr_t *addr, hsk_netaddr_t *na);

bool
hsk_addr_from_sa(hsk_addr_t *addr, const struct sockaddr *sa);

bool
hsk_addr_to_sa(const hsk_addr_t *addr, struct sockaddr *sa);

bool
hsk_addr_from_ip(
  hsk_addr_t *addr,
  uint16_t af,
  const uint8_t *ip,
  uint16_t port
);

bool
hsk_addr_to_ip(
  const hsk_addr_t *addr,
  uint16_t *af,
  uint8_t *ip,
  uint16_t *port
);

bool
hsk_addr_from_string(hsk_addr_t *addr, const char *src, uint16_t port);

bool
hsk_addr_to_string(
  const hsk_addr_t *addr,
  char *dst,
  size_t dst_len,
  uint16_t fb
);

bool
hsk_addr_to_full(
  const hsk_addr_t *addr,
  char *dst,
  size_t dst_len,
  uint16_t fb
);

bool
hsk_addr_to_at(const hsk_addr_t *addr, char *dst, size_t dst_len, uint16_t fb);

bool
hsk_addr_localize(hsk_addr_t *addr);

bool
hsk_sa_from_string(struct sockaddr *sa, const char *src, uint16_t port);

bool
hsk_sa_to_string(
  const struct sockaddr *sa,
  char *dst,
  size_t dst_len,
  uint16_t fb
);

bool
hsk_sa_to_at(
  const struct sockaddr *sa,
  char *dst,
  size_t dst_len,
  uint16_t fb
);

bool
hsk_sa_copy(struct sockaddr *sa, const struct sockaddr *other);

bool
hsk_sa_localize(struct sockaddr *sa);

uint32_t
hsk_addr_hash(const void *key);

bool
hsk_addr_equal(const void *a, const void *b);

bool
hsk_addr_is_null(const hsk_addr_t *addr);

bool
hsk_addr_is_broadcast(const hsk_addr_t *addr);

bool
hsk_addr_is_rfc1918(const hsk_addr_t *addr);

bool
hsk_addr_is_rfc2544(const hsk_addr_t *addr);

bool
hsk_addr_is_rfc3927(const hsk_addr_t *addr);

bool
hsk_addr_is_rfc6598(const hsk_addr_t *addr);

bool
hsk_addr_is_rfc5737(const hsk_addr_t *addr);

bool
hsk_addr_is_rfc3849(const hsk_addr_t *addr);

bool
hsk_addr_is_rfc3964(const hsk_addr_t *addr);

bool
hsk_addr_is_rfc6052(const hsk_addr_t *addr);

bool
hsk_addr_is_rfc4380(const hsk_addr_t *addr);

bool
hsk_addr_is_rfc4862(const hsk_addr_t *addr);

bool
hsk_addr_is_rfc4193(const hsk_addr_t *addr);

bool
hsk_addr_is_rfc6145(const hsk_addr_t *addr);

bool
hsk_addr_is_rfc4843(const hsk_addr_t *addr);

bool
hsk_addr_is_local(const hsk_addr_t *addr);

bool
hsk_addr_is_multicast(const hsk_addr_t *addr);

bool
hsk_addr_is_valid(const hsk_addr_t *addr);

bool
hsk_addr_is_routable(const hsk_addr_t *addr);

void
hsk_addr_print(const hsk_addr_t *addr, const char *prefix);

void
hsk_netaddr_init(hsk_netaddr_t *addr);

bool
hsk_netaddr_read(uint8_t **data, size_t *data_len, hsk_netaddr_t *addr);

int32_t
hsk_netaddr_write(const hsk_netaddr_t *addr, uint8_t **data);
#endif
