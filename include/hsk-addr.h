#ifndef _HSK_ADDR_H
#define _HSK_ADDR_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// INET6_ADDRSTRLEN + 11
#define HSK_MAX_HOST 57

typedef struct hsk_addr_s {
  uint8_t type;
  uint8_t ip[36];
  uint16_t port;
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
hsk_addr_clone(hsk_addr_t *other);

void
hsk_addr_copy(hsk_addr_t *addr, hsk_addr_t *other);

bool
hsk_addr_is_mapped(hsk_addr_t *addr);

bool
hsk_addr_is_ip4(hsk_addr_t *addr);

bool
hsk_addr_is_ip6(hsk_addr_t *addr);

bool
hsk_addr_is_onion(hsk_addr_t *addr);

uint16_t
hsk_addr_get_af(hsk_addr_t *addr);

uint8_t
hsk_addr_get_type(hsk_addr_t *addr);

bool
hsk_addr_set_type(hsk_addr_t *addr, uint8_t type);

uint8_t *
hsk_addr_get_ip(hsk_addr_t *addr);

bool
hsk_addr_set_ip(hsk_addr_t *addr, uint16_t af, uint8_t *ip);

uint16_t
hsk_addr_get_port(hsk_addr_t *addr);

bool
hsk_addr_set_port(hsk_addr_t *addr, uint16_t port);

bool
hsk_addr_from_na(hsk_addr_t *addr, hsk_netaddr_t *na);

bool
hsk_addr_to_na(hsk_addr_t *addr, hsk_netaddr_t *na);

bool
hsk_addr_from_sa(hsk_addr_t *addr, struct sockaddr *sa);

bool
hsk_addr_to_sa(hsk_addr_t *addr, struct sockaddr *sa);

bool
hsk_addr_from_ip(hsk_addr_t *addr, uint16_t af, uint8_t *ip, uint16_t port);

bool
hsk_addr_to_ip(hsk_addr_t *addr, uint16_t *af, uint8_t *ip, uint16_t *port);

bool
hsk_addr_from_string(hsk_addr_t *addr, char *src, uint16_t port);

bool
hsk_addr_to_string(hsk_addr_t *addr, char *dst, size_t dst_len, uint16_t fb);

bool
hsk_sa_from_string(struct sockaddr *sa, char *src, uint16_t port);

bool
hsk_sa_to_string(
  struct sockaddr *sa,
  char *dst,
  size_t dst_len,
  uint16_t fb
);

void
hsk_sa_copy(struct sockaddr *sa, struct sockaddr *other);

uint32_t
hsk_addr_hash(void *key);

bool
hsk_addr_equal(void *a, void *b);

bool
hsk_addr_is_null(hsk_addr_t *addr);

bool
hsk_addr_is_broadcast(hsk_addr_t *addr);

bool
hsk_addr_is_rfc1918(hsk_addr_t *addr);

bool
hsk_addr_is_rfc2544(hsk_addr_t *addr);

bool
hsk_addr_is_rfc3927(hsk_addr_t *addr);

bool
hsk_addr_is_rfc6598(hsk_addr_t *addr);

bool
hsk_addr_is_rfc5737(hsk_addr_t *addr);

bool
hsk_addr_is_rfc3849(hsk_addr_t *addr);

bool
hsk_addr_is_rfc3964(hsk_addr_t *addr);

bool
hsk_addr_is_rfc6052(hsk_addr_t *addr);

bool
hsk_addr_is_rfc4380(hsk_addr_t *addr);

bool
hsk_addr_is_rfc4862(hsk_addr_t *addr);

bool
hsk_addr_is_rfc4193(hsk_addr_t *addr);

bool
hsk_addr_is_rfc6145(hsk_addr_t *addr);

bool
hsk_addr_is_rfc4843(hsk_addr_t *addr);

bool
hsk_addr_is_local(hsk_addr_t *addr);

bool
hsk_addr_is_multicast(hsk_addr_t *addr);

bool
hsk_addr_is_valid(hsk_addr_t *addr);

bool
hsk_addr_is_routable(hsk_addr_t *addr);

void
hsk_addr_print(hsk_addr_t *addr, char *prefix);

void
hsk_netaddr_init(hsk_netaddr_t *addr);

bool
hsk_netaddr_read(uint8_t **data, size_t *data_len, hsk_netaddr_t *addr);

int32_t
hsk_netaddr_write(hsk_netaddr_t *addr, uint8_t **data);
#endif
