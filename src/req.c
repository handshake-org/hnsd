#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "ldns/ldns.h"

#include "hsk-addr.h"
#include "hsk-constants.h"
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
  ldns_pkt *pkt = NULL;
  char *name = NULL;
  ldns_rdf *tld_rdf = NULL;
  char *tld = NULL;
  size_t tld_size = 0;

  req = hsk_dns_req_alloc();

  if (!req)
    goto fail;

  if (ldns_wire2pkt(&pkt, data, data_len) != LDNS_STATUS_OK)
    goto fail;

  ldns_pkt_opcode opcode = ldns_pkt_get_opcode(pkt);
  ldns_pkt_rcode rcode = ldns_pkt_get_rcode(pkt);
  ldns_rr_list *qd = ldns_pkt_question(pkt);
  ldns_rr_list *an = ldns_pkt_answer(pkt);
  ldns_rr_list *ns = ldns_pkt_authority(pkt);

  if (opcode != LDNS_PACKET_QUERY
      || rcode != LDNS_RCODE_NOERROR
      || ldns_rr_list_rr_count(qd) != 1
      || ldns_rr_list_rr_count(an) != 0
      || ldns_rr_list_rr_count(ns) != 0) {
    goto fail;
  }

  // Grab the first question.
  ldns_rr *qs = ldns_rr_list_rr(qd, 0);
  ldns_rr_class class = ldns_rr_get_class(qs);

  if (class != LDNS_RR_CLASS_IN)
    goto fail;

  // Get the fully qualified domain name.
  ldns_rdf *name_rdf = ldns_rr_owner(qs);

  // Convert to C string.
  name = ldns_rdf2str(name_rdf);

  if (!name)
    goto fail;

  // Ensure we have an FQDN.
  size_t name_size = strlen(name);

  if (name_size == 0
      || name_size > 255
      || name[name_size - 1] != '.'
      || strstr(name, "\\")) {
    goto fail;
  }

  // Check for a TLD.
  size_t labels = ldns_dname_label_count(name_rdf);

  if (labels != 0) {
    tld_rdf = ldns_dname_label(name_rdf, labels - 1);

    if (!tld_rdf)
      goto fail;

    tld = ldns_rdf2str(tld_rdf);

    if (!tld)
      goto fail;

    tld_size = strlen(tld);

    if (tld_size == 0
        || tld_size > 255
        || strstr(tld, "\\")) {
      goto fail;
    }

    assert(tld[tld_size - 1] == '.');

    tld[tld_size - 1] = '\0';
    tld_size -= 1;

    // Lowercase.
    int32_t i;
    for (i = 0; i < tld_size; i++) {
      char ch = tld[i];
      if (ch >= 'A' && ch <= 'Z')
        tld[i] += ' ';
    }
  }

  // Reference.
  req->ns = NULL;

  // DNS stuff.
  req->id = ldns_pkt_id(pkt);
  req->labels = labels;
  memcpy(req->name, name, name_size + 1);
  req->type = (uint16_t)ldns_rr_get_type(qs);
  req->class = (uint16_t)class;
  req->edns = ldns_pkt_edns_udp_size(pkt) == 4096;
  req->dnssec = ldns_pkt_edns_do(pkt);

  // HSK stuff.
  if (tld)
    memcpy(req->tld, tld, tld_size + 1);

  // Sender address.
  hsk_sa_copy(req->addr, addr);

  // Free stuff up.
  ldns_pkt_free(pkt);

  free(name);

  if (tld) {
    ldns_rdf_deep_free(tld_rdf);
    free(tld);
  }

  return req;

fail:
  if (req)
    free(req);

  if (pkt)
    ldns_pkt_free(pkt);

  if (name)
    free(name);

  if (tld_rdf)
    ldns_rdf_deep_free(tld_rdf);

  if (tld)
    free(tld);

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
