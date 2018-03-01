#ifndef _HSK_REQ_H
#define _HSK_REQ_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

typedef struct {
  // Reference.
  void *ns;

  // DNS stuff
  uint16_t id;
  size_t labels;
  char name[256];
  uint16_t type;
  uint16_t class;
  bool edns;
  bool dnssec;

  // HSK stuff
  char tld[256];
  uint8_t nonce[32];

  // Who it's from.
  struct sockaddr_storage ss;
  struct sockaddr *addr;
} hsk_dns_req_t;

void
hsk_dns_req_init(hsk_dns_req_t *req);

void
hsk_dns_req_uninit(hsk_dns_req_t *req);

hsk_dns_req_t *
hsk_dns_req_alloc(void);

void
hsk_dns_req_free(hsk_dns_req_t *req);

hsk_dns_req_t *
hsk_dns_req_create(uint8_t *data, size_t data_len, struct sockaddr *addr);
#endif
