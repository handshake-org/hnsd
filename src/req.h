#ifndef _HSK_REQ_H
#define _HSK_REQ_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "dns.h"

typedef struct {
  // Reference.
  void *ns;

  // DNS stuff
  uint16_t id;
  size_t labels;
  char name[HSK_DNS_MAX_NAME + 1];
  uint16_t type;
  uint16_t class;
  bool rd;
  bool cd;
  bool edns;
  size_t max_size;
  bool dnssec;

  // HSK stuff
  char tld[HSK_DNS_MAX_LABEL + 1];

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

void
hsk_dns_req_print(hsk_dns_req_t *req, char *prefix);
#endif
