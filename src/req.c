#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "hsk-addr.h"
#include "hsk-constants.h"
#include "dns.h"
#include "hsk-error.h"
#include "req.h"
#include "utils.h"

void
hsk_dns_req_init(hsk_dns_req_t *req) {
  assert(req);
  req->ns = NULL;
  req->id = 0;
  req->labels = 0;
  memset(req->name, 0x00, sizeof(req->name));
  req->type = 0;
  req->class = 0;
  req->edns = false;
  req->dnssec = false;
  memset(req->tld, 0x00, sizeof(req->tld));
  memset(&req->ss, 0x00, sizeof(struct sockaddr_storage));
  req->addr = (struct sockaddr *)&req->ss;
}

void
hsk_dns_req_uninit(hsk_dns_req_t *req) {
  assert(req);
}

hsk_dns_req_t *
hsk_dns_req_alloc(void) {
  hsk_dns_req_t *req = malloc(sizeof(hsk_dns_req_t));
  if (req)
    hsk_dns_req_init(req);
  return req;
}

void
hsk_dns_req_free(hsk_dns_req_t *req) {
  assert(req);
  hsk_dns_req_uninit(req);
  free(req);
}

hsk_dns_req_t *
hsk_dns_req_create(uint8_t *data, size_t data_len, struct sockaddr *addr) {
  hsk_dns_req_t *req = NULL;
  hsk_dns_msg_t *msg = NULL;

  req = hsk_dns_req_alloc();

  if (!req)
    goto fail;

  if (!hsk_dns_msg_decode(data, data_len, &msg))
    goto fail;

  if (msg->opcode != HSK_DNS_QUERY
      || msg->code != HSK_DNS_NOERROR
      || msg->qd.size != 1
      || msg->an.size != 0
      || msg->ns.size != 0) {
    goto fail;
  }

  // Grab the first question.
  hsk_dns_qs_t *qs = msg->qd.items[0];

  if (qs->class != HSK_DNS_IN)
    goto fail;

  // Don't allow dirty names.
  if (hsk_dns_name_dirty(qs->name))
    goto fail;

  // Check for a TLD.
  hsk_dns_label_get(qs->name, -1, req->tld);

  // Lowercase.
  char *s = req->tld;
  while (*s) {
    if (*s >= 'A' && *s <= 'Z')
      *s += ' ';
    s += 1;
  }

  // Reference.
  req->ns = NULL;

  // DNS stuff.
  req->id = msg->id;
  req->labels = hsk_dns_label_count(qs->name);
  strcpy(req->name, qs->name);
  req->type = qs->type;
  req->class = qs->class;
  req->edns = msg->edns.enabled;
  req->dnssec = (msg->edns.flags & HSK_DNS_DO) != 0;

  // Sender address.
  hsk_sa_copy(req->addr, addr);

  // Free stuff up.
  hsk_dns_msg_free(msg);

  return req;

fail:
  if (req)
    free(req);

  if (msg)
    hsk_dns_msg_free(msg);

  return NULL;
}

void
hsk_dns_req_print(hsk_dns_req_t *req, char *prefix) {
  assert(req);

  if (!prefix)
    prefix = "";

  char addr[HSK_MAX_HOST];

  assert(hsk_sa_to_string(req->addr, addr, HSK_MAX_HOST, 1));

  printf("%squery\n", prefix);
  printf("%s  id=%d\n", prefix, req->id);
  printf("%s  labels=%d\n", prefix, req->labels);
  printf("%s  name=%s\n", prefix, req->name);
  printf("%s  type=%d\n", prefix, req->type);
  printf("%s  class=%d\n", prefix, req->class);
  printf("%s  edns=%d\n", prefix, (int32_t)req->edns);
  printf("%s  dnssec=%d\n", prefix, (int32_t)req->dnssec);
  printf("%s  tld=%s\n", prefix, req->tld);
  printf("%s  addr=%s\n", prefix, addr);
}
