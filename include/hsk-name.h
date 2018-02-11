#ifndef _HSK_NAME_H
#define _HSK_NAME_H

#include <netdb.h>
#include <stdint.h>
#include <stdbool.h>

#include "hsk-proof.h"

#define IPPROTO_HSK 0x6c68736b

bool
hsk_is_hskn(char *name, size_t len);

bool
hsk_is_hsk(char *name);

bool
hsk_is_sld(char *name);

char *
hsk_to_tld(char *name);

int32_t
hsk_get_proof(char *name, hsk_proof_t **proof);

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
