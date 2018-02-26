#ifndef _HSK_ADDR_H
#define _HSK_ADDR_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "hsk-msg.h"

typedef struct sockaddr_storage hsk_addr_t;

uint16_t
hsk_addr_get_af(hsk_addr_t *addr);

bool
hsk_addr_set_af(hsk_addr_t *addr, uint16_t af);

bool
hsk_addr_is_valid(hsk_addr_t *addr);

uint8_t *
hsk_addr_get_ip(hsk_addr_t *addr);

uint8_t *
hsk_addr_get_ip4(hsk_addr_t *addr);

uint8_t *
hsk_addr_get_ip6(hsk_addr_t *addr);

bool
hsk_addr_set_ip(hsk_addr_t *addr, uint8_t *ip);

uint16_t
hsk_addr_get_port(hsk_addr_t *addr);

bool
hsk_addr_set_port(hsk_addr_t *addr, uint16_t port);

void
hsk_addr_init(hsk_addr_t *addr);

hsk_addr_t *
hsk_addr_alloc(void);

void
hsk_addr_copy(hsk_addr_t *addr, hsk_addr_t *other);

uint16_t
hsk_addr_na_type(uint8_t *ip);

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
hsk_addr_from_string(hsk_addr_t *addr, char *ip, uint16_t port);

bool
hsk_addr_to_string(hsk_addr_t *addr, char *ip, uint16_t fallback);

static inline uint32_t
hsk_hash_data(uint32_t hash, uint8_t *data, size_t size);

uint32_t
hsk_addr_hash(void *key);

bool
hsk_addr_equal(void *a, void *b);
#endif
