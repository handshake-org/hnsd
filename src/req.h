#ifndef _HSK_REQ_H
#define _HSK_REQ_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "dns.h"
#include "ec.h"
#include "platform-net.h"

typedef struct {
  // Reference.
  void *ns;

  // DNS stuff
  uint16_t id;
  size_t labels;
  uint8_t name[HSK_DNS_MAX_NAME];
  uint16_t type;
  uint16_t class;
  bool rd;
  bool cd;
  bool ad;
  bool edns;
  size_t max_size;
  bool dnssec;

  // For Unbound
  char namestr[HSK_DNS_MAX_NAME_STRING];

  // HSK stuff
  uint8_t tld[HSK_DNS_MAX_LABEL + 2];

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
hsk_dns_req_create(
  const uint8_t *data,
  size_t data_len,
  const struct sockaddr *addr
);

void
hsk_dns_req_print(const hsk_dns_req_t *req, const char *prefix);

bool
hsk_dns_msg_finalize(
  hsk_dns_msg_t **res,
  const hsk_dns_req_t *req,
  const hsk_ec_t *ec,
  const uint8_t *key,
  uint8_t **wire,
  size_t *wire_len
);
#endif
