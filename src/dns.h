#ifndef _HSK_DNS_H
#define _HSK_DNS_H

#if !defined(WIN32) || defined(WATT32)
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif
#include <strings.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <stdint.h>
#include <limits.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <errno.h>
#include <ctype.h>

#include "proof.h"

// Other defs
#define IPPROTO_HSK 0x6c68736b

typedef struct {
  int32_t status;
  int32_t timeouts;
  struct hostent *host;
} _hsk_hostent_ret_t;

typedef struct {
  int32_t status;
  int32_t timeouts;
  uint8_t *abuf;
  int32_t alen;
} _hsk_query_ret_t;

typedef struct {
  const char *host;
  int32_t port;
} _hsk_ns_t;

bool
hsk_is_hskn(const char *name, size_t len);

bool
hsk_is_hsk(const char *name);

bool
hsk_is_tld(const char *name);

char *
hsk_to_tld(const char *name);

int32_t
hsk_getproof(const char *name, hsk_proof_t **proof);

void
hsk_cleanup();

void
hsk_freehostent(struct hostent *ip);

struct hostent *
hsk_gethostbyname(const char *name);

struct hostent *
hsk_gethostbyname2(const char *name, int32_t af);

void
hsk_freeaddrinfo(struct addrinfo *ai);

int32_t
hsk_getaddrinfo(
  const char *node,
  const char *service,
  const struct addrinfo *hints,
  struct addrinfo **res
);

#endif
