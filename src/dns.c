#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>

#include "bio.h"
#include "dns.h"
#include "utils.h"
#include "sha256.h"
#include "ecc.h"

typedef struct hsk_dns_raw_rr_s {
  uint8_t *data;
  size_t size;
} hsk_dns_raw_rr_t;

static void
to_lower(char *name);

static int32_t
raw_rr_cmp(const void *a, const void *b);

static bool
raw_rr_equal(hsk_dns_raw_rr_t *a, hsk_dns_raw_rr_t *b);

/*
 * Message
 */

void
hsk_dns_msg_init(hsk_dns_msg_t *msg) {
  assert(msg);
  msg->id = 0;
  msg->opcode = 0;
  msg->code = 0;
  msg->flags = 0;
  hsk_dns_rrs_init(&msg->qd);
  hsk_dns_rrs_init(&msg->an);
  hsk_dns_rrs_init(&msg->ns);
  hsk_dns_rrs_init(&msg->ar);
  msg->edns.enabled = false;
  msg->edns.version = 0;
  msg->edns.flags = 0;
  msg->edns.size = 0;
  msg->edns.code = 0;
  msg->edns.rd_len = 0;
  msg->edns.rd = NULL;
}

void
hsk_dns_msg_uninit(hsk_dns_msg_t *msg) {
  assert(msg);

  hsk_dns_rrs_uninit(&msg->qd);
  hsk_dns_rrs_uninit(&msg->an);
  hsk_dns_rrs_uninit(&msg->ns);
  hsk_dns_rrs_uninit(&msg->ar);

  if (msg->edns.rd) {
    free(msg->edns.rd);
    msg->edns.rd_len = 0;
    msg->edns.rd = NULL;
  }
}

hsk_dns_msg_t *
hsk_dns_msg_alloc(void) {
  hsk_dns_msg_t *msg = malloc(sizeof(hsk_dns_msg_t));
  if (msg)
    hsk_dns_msg_init(msg);
  return msg;
}

void
hsk_dns_msg_free(hsk_dns_msg_t *msg) {
  assert(msg);
  hsk_dns_msg_uninit(msg);
  free(msg);
}

bool
hsk_dns_msg_decode(uint8_t *data, size_t data_len, hsk_dns_msg_t **msg) {
  hsk_dns_msg_t *m = hsk_dns_msg_alloc();

  if (!m)
    return false;

  if (!hsk_dns_msg_read(&data, &data_len, m)) {
    hsk_dns_msg_free(m);
    return false;
  }

  *msg = m;

  return true;
}

int32_t
hsk_dns_msg_write(hsk_dns_msg_t *msg, uint8_t **data) {
  int32_t size = 0;
  uint16_t flags = msg->flags;

  flags &= ~(0x0f << 11);
  flags &= ~0x0f;
  flags |= ((uint16_t)(msg->opcode & 0x0f)) << 11;
  flags |= msg->code & 0x0f;

  size += write_u16be(data, msg->id);
  size += write_u16be(data, flags);
  size += write_u16be(data, msg->qd.size);
  size += write_u16be(data, msg->an.size);
  size += write_u16be(data, msg->ns.size);
  size += write_u16be(data, msg->ar.size + (msg->edns.enabled ? 1 : 0));

  int32_t i;

  for (i = 0; i < msg->qd.size; i++)
    size += hsk_dns_qs_write(msg->qd.items[i], data);

  for (i = 0; i < msg->an.size; i++)
    size += hsk_dns_rr_write(msg->an.items[i], data);

  for (i = 0; i < msg->ns.size; i++)
    size += hsk_dns_rr_write(msg->ns.items[i], data);

  for (i = 0; i < msg->ar.size; i++)
    size += hsk_dns_rr_write(msg->ar.items[i], data);

  if (msg->code > 0x0f) {
    msg->edns.enabled = true;
    msg->edns.code = msg->code >> 4;
  }

  if (msg->edns.enabled) {
    hsk_dns_rr_t rr = { .type = HSK_DNS_OPT };
    hsk_dns_opt_rd_t rd;
    strcpy(rr.name, ".");
    rr.ttl = 0;
    rr.ttl |= ((uint32_t)msg->edns.code) << 24;
    rr.ttl |= ((uint32_t)msg->edns.version) << 16;
    rr.ttl |= (uint32_t)msg->edns.flags;
    rr.class = msg->edns.size;
    rr.rd = (void *)&rd;
    rd.rd_len = msg->edns.rd_len;
    rd.rd = msg->edns.rd;
    size += hsk_dns_rr_write(&rr, data);
  }

  return size;
}

int32_t
hsk_dns_msg_size(hsk_dns_msg_t *msg) {
  return hsk_dns_msg_write(msg, NULL);
}

bool
hsk_dns_msg_encode(hsk_dns_msg_t *msg, uint8_t **data, size_t *data_len) {
  int32_t size = hsk_dns_msg_size(msg);
  uint8_t *buf = malloc(size);

  if (!buf)
    return false;

  uint8_t *b = buf;
  hsk_dns_msg_write(msg, &b);

  *data = buf;
  *data_len = size;

  return true;
}

bool
hsk_dns_msg_read(uint8_t **data, size_t *data_len, hsk_dns_msg_t *msg) {
  uint8_t *pd = *data;
  size_t pd_len = *data_len;
  uint16_t id = 0;
  uint16_t flags = 0;
  uint16_t qdcount = 0;
  uint16_t ancount = 0;
  uint16_t nscount = 0;
  uint16_t arcount = 0;

  if (!read_u16be(data, data_len, &id))
    return false;

  if (!read_u16be(data, data_len, &flags))
    return false;

  if (!read_u16be(data, data_len, &qdcount))
    return false;

  if (!read_u16be(data, data_len, &ancount))
    return false;

  if (!read_u16be(data, data_len, &nscount))
    return false;

  if (!read_u16be(data, data_len, &arcount))
    return false;

  msg->id = id;
  msg->opcode = (flags >> 11) & 0x0f;
  msg->code = flags & 0x0f;
  msg->flags = flags;

  uint32_t i;

  for (i = 0; i < qdcount; i++) {
    if (*data_len == 0)
      break;

    hsk_dns_qs_t *qs = hsk_dns_qs_alloc();

    if (!qs)
      goto fail;

    if (!hsk_dns_qs_read(data, data_len, pd, pd_len, qs))
      goto fail;

    hsk_dns_rrs_push(&msg->qd, qs);
  }

  for (i = 0; i < ancount; i++) {
    if (msg->flags & HSK_DNS_TC) {
      if (*data_len == 0)
        break;
    }

    hsk_dns_rr_t *rr = hsk_dns_rr_alloc();

    if (!rr)
      goto fail;

    if (!hsk_dns_rr_read(data, data_len, pd, pd_len, rr))
      goto fail;

    hsk_dns_rrs_push(&msg->an, rr);
  }

  for (i = 0; i < nscount; i++) {
    if (msg->flags & HSK_DNS_TC) {
      if (*data_len == 0)
        break;
    }

    hsk_dns_rr_t *rr = hsk_dns_rr_alloc();

    if (!rr)
      goto fail;

    if (!hsk_dns_rr_read(data, data_len, pd, pd_len, rr))
      goto fail;

    hsk_dns_rrs_push(&msg->ns, rr);
  }

  for (i = 0; i < arcount; i++) {
    if (*data_len == 0)
      break;

    hsk_dns_rr_t *rr = hsk_dns_rr_alloc();

    if (!rr)
      goto fail;

    if (!hsk_dns_rr_read(data, data_len, pd, pd_len, rr))
      goto fail;

    if (rr->type == HSK_DNS_OPT) {
      hsk_dns_opt_rd_t *opt = (hsk_dns_opt_rd_t *)rr->rd;

      if (msg->edns.enabled) {
        free(rr->rd);
        free(rr);
        continue;
      }

      msg->edns.enabled = true;
      msg->edns.code = (rr->ttl >> 24) & 0xff;
      msg->edns.version = (rr->ttl >> 16) & 0xff;
      msg->edns.flags = rr->ttl & 0xffff;
      msg->edns.size = rr->class;
      msg->edns.rd_len = opt->rd_len;
      msg->edns.rd = opt->rd;
      msg->code |= msg->edns.code << 4;

      free(rr->rd);
      free(rr);

      continue;
    }

    hsk_dns_rrs_push(&msg->ar, rr);
  }

  return true;

fail:
  hsk_dns_rrs_uninit(&msg->qd);
  hsk_dns_rrs_uninit(&msg->an);
  hsk_dns_rrs_uninit(&msg->ns);
  hsk_dns_rrs_uninit(&msg->ar);
  hsk_dns_msg_init(msg);
  return false;
}

/*
 * RRSet
 */

void
hsk_dns_rrs_init(hsk_dns_rrs_t *rrs) {
  memset(rrs->items, 0, sizeof(hsk_dns_rr_t *) * 255);
  rrs->size = 0;
}

void
hsk_dns_rrs_uninit(hsk_dns_rrs_t *rrs) {
  assert(rrs);

  int32_t i;
  for (i = 0; i < rrs->size; i++) {
    assert(rrs->items[i]);
    hsk_dns_rr_free(rrs->items[i]);
    rrs->items[i] = NULL;
  }

  rrs->size = 0;
}

hsk_dns_rrs_t *
hsk_dns_rrs_alloc(void) {
  hsk_dns_rrs_t *rrs = malloc(sizeof(hsk_dns_rrs_t));
  if (rrs)
    hsk_dns_rrs_init(rrs);
  return rrs;
}

void
hsk_dns_rrs_free(hsk_dns_rrs_t *rrs) {
  assert(rrs);
  hsk_dns_rrs_uninit(rrs);
  free(rrs);
}

size_t
hsk_dns_rrs_unshift(hsk_dns_rrs_t *rrs, hsk_dns_rr_t *rr) {
  if (rrs->size == 255)
    return 0;

  assert(rrs->size < 255);

  int32_t i;
  for (i = 1; i < rrs->size + 1; i++) {
    assert(rrs->items[i - 1]);
    rrs->items[i] = rrs->items[i - 1];
  }

  rrs->items[i] = rr;
  rrs->size += 1;

  return rrs->size;
}

hsk_dns_rr_t *
hsk_dns_rrs_shift(hsk_dns_rrs_t *rrs) {
  if (rrs->size == 0)
    return NULL;

  hsk_dns_rr_t *rr = rrs->items[0];

  int32_t i;
  for (i = 0; i < rrs->size - 1; i++) {
    assert(rrs->items[i]);
    rrs->items[i] = rrs->items[i + 1];
  }

  rrs->items[rrs->size - 1] = NULL;

  rrs->size -= 1;

  return rr;
}

size_t
hsk_dns_rrs_push(hsk_dns_rrs_t *rrs, hsk_dns_rr_t *rr) {
  if (rrs->size == 255)
    return 0;

  assert(rrs->size < 255);

  assert(!rrs->items[rrs->size]);
  rrs->items[rrs->size] = rr;
  rrs->size += 1;

  return rrs->size;
}

hsk_dns_rr_t *
hsk_dns_rrs_pop(hsk_dns_rrs_t *rrs) {
  if (rrs->size == 0)
    return NULL;

  hsk_dns_rr_t *rr = rrs->items[rrs->size - 1];
  assert(rr);

  rrs->items[rrs->size - 1] = NULL;

  rrs->size -= 1;

  return rr;
}

hsk_dns_rr_t *
hsk_dns_rrs_get(hsk_dns_rrs_t *rrs, int32_t index) {
  assert(rrs);

  if (index < 0)
    index += rrs->size;

  if (index >= rrs->size)
    return NULL;

  return rrs->items[index];
}

size_t
hsk_dns_rrs_set(hsk_dns_rrs_t *rrs, int32_t index, hsk_dns_rr_t *rr) {
  assert(rrs && rr);

  if (index < 0)
    index += rrs->size;

  if (index >= rrs->size)
    return 0;

  rrs->items[index] = rr;
  return rrs->size;
}

/*
 * Question
 */

void
hsk_dns_qs_init(hsk_dns_qs_t *qs) {
  assert(qs);

  memset(qs->name, 0, sizeof(qs->name));
  qs->type = 0;
  qs->class = 0;
  qs->ttl = 0;
  qs->rd = NULL;
}

void
hsk_dns_qs_uninit(hsk_dns_qs_t *qs) {
  return;
}

hsk_dns_qs_t *
hsk_dns_qs_alloc(void) {
  hsk_dns_qs_t *qs = malloc(sizeof(hsk_dns_qs_t));
  if (qs)
    hsk_dns_qs_init(qs);
  return qs;
}

void
hsk_dns_qs_free(hsk_dns_qs_t *qs) {
  assert(qs);
  free(qs);
}

void
hsk_dns_qs_set(hsk_dns_qs_t *qs, char *name, uint16_t type) {
  assert(qs && name);
  assert(strlen(name) <= 255);
  strcpy(qs->name, name);
  qs->type = type;
}

int32_t
hsk_dns_qs_write(hsk_dns_qs_t *qs, uint8_t **data) {
  int32_t size = 0;
  size += hsk_dns_name_write(qs->name, data);
  size += write_u16be(data, qs->type);
  size += write_u16be(data, qs->class);
  return size;
}

bool
hsk_dns_qs_read(
  uint8_t **data,
  size_t *data_len,
  uint8_t *pd,
  size_t pd_len,
  hsk_dns_qs_t *qs
) {
  if (!hsk_dns_name_read(data, data_len, pd, pd_len, qs->name))
    return false;

  if (!read_u16be(data, data_len, &qs->type))
    return false;

  if (!read_u16be(data, data_len, &qs->class))
    return false;

  return true;
}

/*
 * Record
 */

void
hsk_dns_rr_init(hsk_dns_rr_t *rr) {
  assert(rr);

  memset(rr->name, 0, sizeof(rr->name));
  rr->type = 0;
  rr->class = 0;
  rr->ttl = 0;
  rr->rd = NULL;
}

void
hsk_dns_rr_uninit(hsk_dns_rr_t *rr) {
  assert(rr);

  if (rr->rd) {
    hsk_dns_rd_free(rr->rd, rr->type);
    rr->rd = NULL;
  }
}

hsk_dns_rr_t *
hsk_dns_rr_alloc(void) {
  hsk_dns_rr_t *rr = malloc(sizeof(hsk_dns_rr_t));
  if (rr)
    hsk_dns_rr_init(rr);
  return rr;
}

hsk_dns_rr_t *
hsk_dns_rr_create(uint16_t type) {
  hsk_dns_rr_t *rr = hsk_dns_rr_alloc();

  if (!rr)
    return NULL;

  void *rd = hsk_dns_rd_alloc(type);

  if (!rd) {
    free(rr);
    return NULL;
  }

  rr->type = type;
  rr->class = HSK_DNS_IN;
  rr->rd = rd;

  return rr;
}

void
hsk_dns_rr_free(hsk_dns_rr_t *rr) {
  assert(rr);
  hsk_dns_rr_uninit(rr);
  free(rr);
}

void
hsk_dns_rr_set_name(hsk_dns_rr_t *rr, char *name) {
  assert(rr);
  assert(hsk_dns_name_verify(name));

  if (hsk_dns_name_is_fqdn(name))
    strcpy(rr->name, name);
  else
    sprintf(rr->name, "%s.", name);
}

int32_t
hsk_dns_rr_write(hsk_dns_rr_t *rr, uint8_t **data) {
  int32_t size = 0;

  size += hsk_dns_name_write(rr->name, data);
  size += write_u16be(data, rr->type);
  size += write_u16be(data, rr->class);
  size += write_u32be(data, rr->ttl);

  if (!rr->rd) {
    size += write_u16be(data, 0);
    return size;
  }

  size += write_u16be(data, hsk_dns_rd_size(rr->rd, rr->type));
  size += hsk_dns_rd_write(rr->rd, rr->type, data);

  return size;
}

int32_t
hsk_dns_rr_size(hsk_dns_rr_t *rr) {
  return hsk_dns_rr_write(rr, NULL);
}

bool
hsk_dns_rr_read(
  uint8_t **data,
  size_t *data_len,
  uint8_t *pd,
  size_t pd_len,
  hsk_dns_rr_t *rr
) {
  if (!hsk_dns_name_read(data, data_len, pd, pd_len, rr->name))
    return false;

  if (!read_u16be(data, data_len, &rr->type))
    return false;

  if (!read_u16be(data, data_len, &rr->class))
    return false;

  if (!read_u32be(data, data_len, &rr->ttl))
    return false;

  uint16_t len;

  if (!read_u16be(data, data_len, &len))
    return false;

  if (*data_len < len)
    return false;

  void *rd = hsk_dns_rd_alloc(rr->type);

  if (!rd)
    return false;

  uint8_t *rdata = *data;
  size_t rdlen = (size_t)len;

  if (!hsk_dns_rd_read(&rdata, &rdlen, pd, pd_len, rd, rr->type)) {
    free(rd);
    return false;
  }

  rr->rd = rd;

  *data += len;
  *data_len -= len;

  return true;
}

bool
hsk_dns_rr_encode(hsk_dns_rr_t *rr, uint8_t **data, size_t *data_len) {
  if (!rr || !data)
    return false;

  size_t size = hsk_dns_rr_size(rr);
  uint8_t *raw = malloc(size);

  if (!raw)
    return false;

  uint8_t *d = raw;
  hsk_dns_rr_write(rr, &d);

  *data = raw;
  *data_len = size;

  return true;
}

bool
hsk_dns_rr_decode(uint8_t *data, size_t data_len, hsk_dns_rr_t **out) {
  if (!data || !out)
    return false;

  hsk_dns_rr_t *rr = hsk_dns_rr_alloc();

  if (!rr)
    return false;

  uint8_t *raw = data;
  size_t size = data_len;

  if (!hsk_dns_rr_read(&raw, &size, NULL, 0, rr)) {
    hsk_dns_rr_free(rr);
    return false;
  }

  *out = rr;

  return true;
}

hsk_dns_rr_t *
hsk_dns_rr_clone(hsk_dns_rr_t *rr) {
  if (!rr)
    return NULL;

  uint8_t *raw;
  size_t size;
  hsk_dns_rr_t *copy;

  if (!hsk_dns_rr_encode(rr, &raw, &size))
    return NULL;

  if (!hsk_dns_rr_decode(raw, size, &copy)) {
    free(raw);
    return NULL;
  }

  free(raw);

  return copy;
}

/*
 * Record Data
 */

void
hsk_dns_rd_init(void *rd, uint16_t type) {
  switch (type) {
    case HSK_DNS_SOA: {
      hsk_dns_soa_rd_t *r = (hsk_dns_soa_rd_t *)rd;
      memset(r->ns, 0, sizeof(r->ns));
      memset(r->mbox, 0, sizeof(r->mbox));
      r->serial = 0;
      r->refresh = 0;
      r->retry = 0;
      r->expire = 0;
      r->minttl = 0;
      break;
    }
    case HSK_DNS_A: {
      hsk_dns_a_rd_t *r = (hsk_dns_a_rd_t *)rd;
      memset(r->addr, 0, 4);
      break;
    }
    case HSK_DNS_AAAA: {
      hsk_dns_aaaa_rd_t *r = (hsk_dns_aaaa_rd_t *)rd;
      memset(r->addr, 0, 16);
      break;
    }
    case HSK_DNS_CNAME: {
      hsk_dns_cname_rd_t *r = (hsk_dns_cname_rd_t *)rd;
      memset(r->target, 0, sizeof(r->target));
      break;
    }
    case HSK_DNS_DNAME: {
      hsk_dns_dname_rd_t *r = (hsk_dns_dname_rd_t *)rd;
      memset(r->target, 0, sizeof(r->target));
      break;
    }
    case HSK_DNS_NS: {
      hsk_dns_ns_rd_t *r = (hsk_dns_ns_rd_t *)rd;
      memset(r->ns, 0, sizeof(r->ns));
      break;
    }
    case HSK_DNS_MX: {
      hsk_dns_mx_rd_t *r = (hsk_dns_mx_rd_t *)rd;
      r->preference = 0;
      memset(r->mx, 0, sizeof(r->mx));
      break;
    }
    case HSK_DNS_PTR: {
      hsk_dns_ptr_rd_t *r = (hsk_dns_ptr_rd_t *)rd;
      memset(r->ptr, 0, sizeof(r->ptr));
      break;
    }
    case HSK_DNS_SRV: {
      hsk_dns_srv_rd_t *r = (hsk_dns_srv_rd_t *)rd;
      r->priority = 0;
      r->weight = 0;
      r->port = 0;
      memset(r->target, 0, sizeof(r->target));
      break;
    }
    case HSK_DNS_TXT: {
      hsk_dns_txt_rd_t *r = (hsk_dns_txt_rd_t *)rd;
      hsk_dns_txts_init(&r->txts);
      break;
    }
    case HSK_DNS_DS: {
      hsk_dns_ds_rd_t *r = (hsk_dns_ds_rd_t *)rd;
      r->key_tag = 0;
      r->algorithm = 0;
      r->digest_type = 0;
      r->digest_len = 0;
      r->digest = NULL;
      break;
    }
    case HSK_DNS_TLSA: {
      hsk_dns_tlsa_rd_t *r = (hsk_dns_tlsa_rd_t *)rd;
      r->usage = 0;
      r->selector = 0;
      r->matching_type = 0;
      r->certificate_len = 0;
      r->certificate = NULL;
      break;
    }
    case HSK_DNS_SSHFP: {
      hsk_dns_sshfp_rd_t *r = (hsk_dns_sshfp_rd_t *)rd;
      r->algorithm = 0;
      r->digest_type = 0;
      r->fingerprint_len = 0;
      r->fingerprint = NULL;
      break;
    }
    case HSK_DNS_OPENPGPKEY: {
      hsk_dns_openpgpkey_rd_t *r = (hsk_dns_openpgpkey_rd_t *)rd;
      r->pubkey_len = 0;
      r->pubkey = NULL;
      break;
    }
    case HSK_DNS_OPT: {
      hsk_dns_opt_rd_t *r = (hsk_dns_opt_rd_t *)rd;
      r->rd_len = 0;
      r->rd = NULL;
      break;
    }
    case HSK_DNS_DNSKEY: {
      hsk_dns_dnskey_rd_t *r = (hsk_dns_dnskey_rd_t *)rd;
      r->flags = 0;
      r->protocol = 0;
      r->algorithm = 0;
      r->pubkey_len = 0;
      r->pubkey = NULL;
      break;
    }
    case HSK_DNS_RRSIG: {
      hsk_dns_rrsig_rd_t *r = (hsk_dns_rrsig_rd_t *)rd;
      r->type_covered = 0;
      r->algorithm = 0;
      r->labels = 0;
      r->orig_ttl = 0;
      r->expiration = 0;
      r->inception = 0;
      r->key_tag = 0;
      memset(r->signer_name, 0, sizeof(r->signer_name));
      r->signature_len = 0;
      r->signature = NULL;
      break;
    }
    case HSK_DNS_URI: {
      hsk_dns_uri_rd_t *r = (hsk_dns_uri_rd_t *)rd;
      r->priority = 0;
      r->weight = 0;
      r->data_len = 0;
      memset(r->data, 0, sizeof(r->data));
      break;
    }
    case HSK_DNS_RP: {
      hsk_dns_rp_rd_t *r = (hsk_dns_rp_rd_t *)rd;
      memset(r->mbox, 0, sizeof(r->mbox));
      memset(r->txt, 0, sizeof(r->txt));
      break;
    }
    case HSK_DNS_NSEC: {
      hsk_dns_nsec_rd_t *r = (hsk_dns_nsec_rd_t *)rd;
      memset(r->next_domain, 0, sizeof(r->next_domain));
      r->type_map_len = 0;
      r->type_map = NULL;
      break;
    }
    default: {
      hsk_dns_unknown_rd_t *r = (hsk_dns_unknown_rd_t *)rd;
      r->rd_len = 0;
      r->rd = NULL;
      break;
    }
  }
}

void
hsk_dns_rd_uninit(void *rd, uint16_t type) {
  assert(rd);

  switch (type) {
    case HSK_DNS_SOA: {
      hsk_dns_soa_rd_t *r = (hsk_dns_soa_rd_t *)rd;
      break;
    }
    case HSK_DNS_A: {
      hsk_dns_a_rd_t *r = (hsk_dns_a_rd_t *)rd;
      break;
    }
    case HSK_DNS_AAAA: {
      hsk_dns_aaaa_rd_t *r = (hsk_dns_aaaa_rd_t *)rd;
      break;
    }
    case HSK_DNS_CNAME: {
      hsk_dns_cname_rd_t *r = (hsk_dns_cname_rd_t *)rd;
      break;
    }
    case HSK_DNS_DNAME: {
      hsk_dns_dname_rd_t *r = (hsk_dns_dname_rd_t *)rd;
      break;
    }
    case HSK_DNS_NS: {
      hsk_dns_ns_rd_t *r = (hsk_dns_ns_rd_t *)rd;
      break;
    }
    case HSK_DNS_MX: {
      hsk_dns_mx_rd_t *r = (hsk_dns_mx_rd_t *)rd;
      break;
    }
    case HSK_DNS_PTR: {
      hsk_dns_ptr_rd_t *r = (hsk_dns_ptr_rd_t *)rd;
      break;
    }
    case HSK_DNS_SRV: {
      hsk_dns_srv_rd_t *r = (hsk_dns_srv_rd_t *)rd;
      break;
    }
    case HSK_DNS_TXT: {
      hsk_dns_txt_rd_t *r = (hsk_dns_txt_rd_t *)rd;
      hsk_dns_txts_uninit(&r->txts);
      break;
    }
    case HSK_DNS_DS: {
      hsk_dns_ds_rd_t *r = (hsk_dns_ds_rd_t *)rd;
      if (r->digest) {
        free(r->digest);
        r->digest = NULL;
      }
      break;
    }
    case HSK_DNS_TLSA: {
      hsk_dns_tlsa_rd_t *r = (hsk_dns_tlsa_rd_t *)rd;
      if (r->certificate) {
        free(r->certificate);
        r->certificate = NULL;
      }
      break;
    }
    case HSK_DNS_SSHFP: {
      hsk_dns_sshfp_rd_t *r = (hsk_dns_sshfp_rd_t *)rd;
      if (r->fingerprint) {
        free(r->fingerprint);
        r->fingerprint = NULL;
      }
      break;
    }
    case HSK_DNS_OPENPGPKEY: {
      hsk_dns_openpgpkey_rd_t *r = (hsk_dns_openpgpkey_rd_t *)rd;
      if (r->pubkey)
        free(r->pubkey);
      break;
    }
    case HSK_DNS_OPT: {
      hsk_dns_opt_rd_t *r = (hsk_dns_opt_rd_t *)rd;
      if (r->rd) {
        free(r->rd);
        r->rd = NULL;
      }
      break;
    }
    case HSK_DNS_DNSKEY: {
      hsk_dns_dnskey_rd_t *r = (hsk_dns_dnskey_rd_t *)rd;
      if (r->pubkey) {
        free(r->pubkey);
        r->pubkey = NULL;
      }
      break;
    }
    case HSK_DNS_RRSIG: {
      hsk_dns_rrsig_rd_t *r = (hsk_dns_rrsig_rd_t *)rd;
      if (r->signature) {
        free(r->signature);
        r->signature = NULL;
      }
      break;
    }
    case HSK_DNS_URI: {
      hsk_dns_uri_rd_t *r = (hsk_dns_uri_rd_t *)rd;
      break;
    }
    case HSK_DNS_RP: {
      hsk_dns_rp_rd_t *r = (hsk_dns_rp_rd_t *)rd;
      break;
    }
    case HSK_DNS_NSEC: {
      hsk_dns_nsec_rd_t *r = (hsk_dns_nsec_rd_t *)rd;
      if (r->type_map) {
        free(r->type_map);
        r->type_map = NULL;
      }
      break;
    }
    default: {
      hsk_dns_unknown_rd_t *r = (hsk_dns_unknown_rd_t *)rd;
      if (r->rd) {
        free(r->rd);
        r->rd = NULL;
      }
      break;
    }
  }
}

void *
hsk_dns_rd_alloc(uint16_t type) {
  void *rd;

  switch (type) {
    case HSK_DNS_SOA: {
      rd = malloc(sizeof(hsk_dns_soa_rd_t));
      break;
    }
    case HSK_DNS_A: {
      rd = malloc(sizeof(hsk_dns_a_rd_t));
      break;
    }
    case HSK_DNS_AAAA: {
      rd = malloc(sizeof(hsk_dns_aaaa_rd_t));
      break;
    }
    case HSK_DNS_CNAME: {
      rd = malloc(sizeof(hsk_dns_cname_rd_t));
      break;
    }
    case HSK_DNS_DNAME: {
      rd = malloc(sizeof(hsk_dns_dname_rd_t));
      break;
    }
    case HSK_DNS_NS: {
      rd = malloc(sizeof(hsk_dns_ns_rd_t));
      break;
    }
    case HSK_DNS_MX: {
      rd = malloc(sizeof(hsk_dns_mx_rd_t));
      break;
    }
    case HSK_DNS_PTR: {
      rd = malloc(sizeof(hsk_dns_ptr_rd_t));
      break;
    }
    case HSK_DNS_SRV: {
      rd = malloc(sizeof(hsk_dns_srv_rd_t));
      break;
    }
    case HSK_DNS_TXT: {
      rd = malloc(sizeof(hsk_dns_txt_rd_t));
      break;
    }
    case HSK_DNS_DS: {
      rd = malloc(sizeof(hsk_dns_ds_rd_t));
      break;
    }
    case HSK_DNS_TLSA: {
      rd = malloc(sizeof(hsk_dns_tlsa_rd_t));
      break;
    }
    case HSK_DNS_SSHFP: {
      rd = malloc(sizeof(hsk_dns_sshfp_rd_t));
      break;
    }
    case HSK_DNS_OPENPGPKEY: {
      rd = malloc(sizeof(hsk_dns_openpgpkey_rd_t));
      break;
    }
    case HSK_DNS_OPT: {
      rd = malloc(sizeof(hsk_dns_opt_rd_t));
      break;
    }
    case HSK_DNS_DNSKEY: {
      rd = malloc(sizeof(hsk_dns_dnskey_rd_t));
      break;
    }
    case HSK_DNS_RRSIG: {
      rd = malloc(sizeof(hsk_dns_rrsig_rd_t));
      break;
    }
    case HSK_DNS_URI: {
      rd = malloc(sizeof(hsk_dns_uri_rd_t));
      break;
    }
    case HSK_DNS_RP: {
      rd = malloc(sizeof(hsk_dns_rp_rd_t));
      break;
    }
    case HSK_DNS_NSEC: {
      rd = malloc(sizeof(hsk_dns_nsec_rd_t));
      break;
    }
    default: {
      rd = malloc(sizeof(hsk_dns_unknown_rd_t));
      break;
    }
  }

  if (rd)
    hsk_dns_rd_init(rd, type);

  return rd;
}

void
hsk_dns_rd_free(void *rd, uint16_t type) {
  assert(rd);
  hsk_dns_rd_uninit(rd, type);
  free(rd);
}

int32_t
hsk_dns_rd_write(void *rd, uint16_t type, uint8_t **data) {
  int32_t size = 0;

  switch (type) {
    case HSK_DNS_SOA: {
      hsk_dns_soa_rd_t *r = (hsk_dns_soa_rd_t *)rd;

      size += hsk_dns_name_write(r->ns, data);
      size += hsk_dns_name_write(r->mbox, data);
      size += write_u32be(data, r->serial);
      size += write_u32be(data, r->refresh);
      size += write_u32be(data, r->retry);
      size += write_u32be(data, r->expire);
      size += write_u32be(data, r->minttl);

      break;
    }
    case HSK_DNS_A: {
      hsk_dns_a_rd_t *r = (hsk_dns_a_rd_t *)rd;

      size += write_bytes(data, r->addr, 4);

      break;
    }
    case HSK_DNS_AAAA: {
      hsk_dns_aaaa_rd_t *r = (hsk_dns_aaaa_rd_t *)rd;

      size += write_bytes(data, r->addr, 16);

      break;
    }
    case HSK_DNS_CNAME: {
      hsk_dns_cname_rd_t *r = (hsk_dns_cname_rd_t *)rd;

      size += hsk_dns_name_write(r->target, data);

      break;
    }
    case HSK_DNS_DNAME: {
      hsk_dns_dname_rd_t *r = (hsk_dns_dname_rd_t *)rd;

      size += hsk_dns_name_write(r->target, data);

      break;
    }
    case HSK_DNS_NS: {
      hsk_dns_ns_rd_t *r = (hsk_dns_ns_rd_t *)rd;

      size += hsk_dns_name_write(r->ns, data);

      break;
    }
    case HSK_DNS_MX: {
      hsk_dns_mx_rd_t *r = (hsk_dns_mx_rd_t *)rd;

      size += write_u16be(data, r->preference);
      size += hsk_dns_name_write(r->mx, data);

      break;
    }
    case HSK_DNS_PTR: {
      hsk_dns_ptr_rd_t *r = (hsk_dns_ptr_rd_t *)rd;

      size += hsk_dns_name_write(r->ptr, data);

      break;
    }
    case HSK_DNS_SRV: {
      hsk_dns_srv_rd_t *r = (hsk_dns_srv_rd_t *)rd;

      size += write_u16be(data, r->priority);
      size += write_u16be(data, r->weight);
      size += write_u16be(data, r->port);
      size += hsk_dns_name_write(r->target, data);

      break;
    }
    case HSK_DNS_TXT: {
      hsk_dns_txt_rd_t *r = (hsk_dns_txt_rd_t *)rd;

      int32_t i;
      for (i = 0; i < r->txts.size; i++) {
        hsk_dns_txt_t *txt = r->txts.items[i];
        assert(txt);
        size += write_u8(data, txt->data_len);
        size += write_bytes(data, txt->data, txt->data_len);
      }

      break;
    }
    case HSK_DNS_DS: {
      hsk_dns_ds_rd_t *r = (hsk_dns_ds_rd_t *)rd;

      size += write_u16be(data, r->key_tag);
      size += write_u8(data, r->algorithm);
      size += write_u8(data, r->digest_type);
      size += write_bytes(data, r->digest, r->digest_len);

      break;
    }
    case HSK_DNS_TLSA: {
      hsk_dns_tlsa_rd_t *r = (hsk_dns_tlsa_rd_t *)rd;

      size += write_u8(data, r->usage);
      size += write_u8(data, r->selector);
      size += write_u8(data, r->matching_type);
      size += write_bytes(data, r->certificate, r->certificate_len);

      break;
    }
    case HSK_DNS_SSHFP: {
      hsk_dns_sshfp_rd_t *r = (hsk_dns_sshfp_rd_t *)rd;

      size += write_u8(data, r->algorithm);
      size += write_u8(data, r->digest_type);
      size += write_bytes(data, r->fingerprint, r->fingerprint_len);

      break;
    }
    case HSK_DNS_OPENPGPKEY: {
      hsk_dns_openpgpkey_rd_t *r = (hsk_dns_openpgpkey_rd_t *)rd;

      size += write_bytes(data, r->pubkey, r->pubkey_len);

      break;
    }
    case HSK_DNS_OPT: {
      hsk_dns_opt_rd_t *r = (hsk_dns_opt_rd_t *)rd;

      size += write_bytes(data, r->rd, r->rd_len);

      break;
    }
    case HSK_DNS_DNSKEY: {
      hsk_dns_dnskey_rd_t *r = (hsk_dns_dnskey_rd_t *)rd;

      size += write_u16be(data, r->flags);
      size += write_u8(data, r->protocol);
      size += write_u8(data, r->algorithm);
      size += write_u8(data, r->pubkey_len);
      size += write_bytes(data, r->pubkey, r->pubkey_len);

      break;
    }
    case HSK_DNS_RRSIG: {
      hsk_dns_rrsig_rd_t *r = (hsk_dns_rrsig_rd_t *)rd;

      size += write_u16be(data, r->type_covered);
      size += write_u8(data, r->algorithm);
      size += write_u8(data, r->labels);
      size += write_u32be(data, r->orig_ttl);
      size += write_u32be(data, r->expiration);
      size += write_u32be(data, r->inception);
      size += write_u16be(data, r->key_tag);
      size += hsk_dns_name_write(r->signer_name, data);
      size += write_bytes(data, r->signature, r->signature_len);

      break;
    }
    case HSK_DNS_URI: {
      hsk_dns_uri_rd_t *r = (hsk_dns_uri_rd_t *)rd;

      size += write_u16be(data, r->priority);
      size += write_u16be(data, r->weight);
      size += write_u8(data, r->data_len);
      size += write_bytes(data, r->data, r->data_len);

      break;
    }
    case HSK_DNS_RP: {
      hsk_dns_rp_rd_t *r = (hsk_dns_rp_rd_t *)rd;

      size += hsk_dns_name_write(r->mbox, data);
      size += hsk_dns_name_write(r->txt, data);

      break;
    }
    case HSK_DNS_NSEC: {
      hsk_dns_nsec_rd_t *r = (hsk_dns_nsec_rd_t *)rd;

      size += hsk_dns_name_write(r->next_domain, data);
      size += write_bytes(data, r->type_map, r->type_map_len);

      break;
    }
    default: {
      hsk_dns_unknown_rd_t *r = (hsk_dns_unknown_rd_t *)rd;

      size += write_bytes(data, r->rd, r->rd_len);

      break;
    }
  }

  return size;
}

int32_t
hsk_dns_rd_size(void *rd, uint16_t type) {
  return hsk_dns_rd_write(rd, type, NULL);
}

bool
hsk_dns_rd_read(
  uint8_t **data,
  size_t *data_len,
  uint8_t *pd,
  size_t pd_len,
  void *rd,
  uint16_t type
) {
  switch (type) {
    case HSK_DNS_SOA: {
      hsk_dns_soa_rd_t *r = (hsk_dns_soa_rd_t *)rd;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->ns))
        return false;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->mbox))
        return false;

      if (!read_u32be(data, data_len, &r->serial))
        return false;

      if (!read_u32be(data, data_len, &r->refresh))
        return false;

      if (!read_u32be(data, data_len, &r->retry))
        return false;

      if (!read_u32be(data, data_len, &r->expire))
        return false;

      if (!read_u32be(data, data_len, &r->minttl))
        return false;

      break;
    }
    case HSK_DNS_A: {
      hsk_dns_a_rd_t *r = (hsk_dns_a_rd_t *)rd;

      if (!read_bytes(data, data_len, r->addr, 4))
        return false;

      break;
    }
    case HSK_DNS_AAAA: {
      hsk_dns_aaaa_rd_t *r = (hsk_dns_aaaa_rd_t *)rd;

      if (!read_bytes(data, data_len, r->addr, 16))
        return false;

      break;
    }
    case HSK_DNS_CNAME: {
      hsk_dns_cname_rd_t *r = (hsk_dns_cname_rd_t *)rd;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->target))
        return false;

      break;
    }
    case HSK_DNS_DNAME: {
      hsk_dns_dname_rd_t *r = (hsk_dns_dname_rd_t *)rd;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->target))
        return false;

      break;
    }
    case HSK_DNS_NS: {
      hsk_dns_ns_rd_t *r = (hsk_dns_ns_rd_t *)rd;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->ns))
        return false;

      break;
    }
    case HSK_DNS_MX: {
      hsk_dns_mx_rd_t *r = (hsk_dns_mx_rd_t *)rd;

      if (!read_u16be(data, data_len, &r->preference))
        return false;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->mx))
        return false;

      break;
    }
    case HSK_DNS_PTR: {
      hsk_dns_ptr_rd_t *r = (hsk_dns_ptr_rd_t *)rd;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->ptr))
        return false;

      break;
    }
    case HSK_DNS_SRV: {
      hsk_dns_srv_rd_t *r = (hsk_dns_srv_rd_t *)rd;

      if (!read_u16be(data, data_len, &r->priority))
        return false;

      if (!read_u16be(data, data_len, &r->weight))
        return false;

      if (!read_u16be(data, data_len, &r->port))
        return false;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->target))
        return false;

      break;
    }
    case HSK_DNS_TXT: {
      hsk_dns_txt_rd_t *r = (hsk_dns_txt_rd_t *)rd;

      while (*data_len > 0) {
        hsk_dns_txt_t *txt = hsk_dns_txt_alloc();

        if (!txt)
          goto fail_txt;

        if (!read_u8(data, data_len, &txt->data_len))
          goto fail_txt;

        if (!read_bytes(data, data_len, txt->data, txt->data_len))
          goto fail_txt;

        hsk_dns_txts_push(&r->txts, txt);
      }

      break;

fail_txt:
      hsk_dns_txts_uninit(&r->txts);
      return false;
    }
    case HSK_DNS_DS: {
      hsk_dns_ds_rd_t *r = (hsk_dns_ds_rd_t *)rd;

      if (!read_u16be(data, data_len, &r->key_tag))
        return false;

      if (!read_u8(data, data_len, &r->algorithm))
        return false;

      if (!read_u8(data, data_len, &r->digest_type))
        return false;

      r->digest_len = *data_len;

      if (!alloc_bytes(data, data_len, &r->digest, *data_len))
        return false;

      break;
    }
    case HSK_DNS_TLSA: {
      hsk_dns_tlsa_rd_t *r = (hsk_dns_tlsa_rd_t *)rd;

      if (!read_u8(data, data_len, &r->usage))
        return false;

      if (!read_u8(data, data_len, &r->selector))
        return false;

      if (!read_u8(data, data_len, &r->matching_type))
        return false;

      r->certificate_len = *data_len;

      if (!alloc_bytes(data, data_len, &r->certificate, *data_len))
        return false;

      break;
    }
    case HSK_DNS_SSHFP: {
      hsk_dns_sshfp_rd_t *r = (hsk_dns_sshfp_rd_t *)rd;

      if (!read_u8(data, data_len, &r->algorithm))
        return false;

      if (!read_u8(data, data_len, &r->digest_type))
        return false;

      r->fingerprint_len = *data_len;

      if (!alloc_bytes(data, data_len, &r->fingerprint, *data_len))
        return false;

      break;
    }
    case HSK_DNS_OPENPGPKEY: {
      hsk_dns_openpgpkey_rd_t *r = (hsk_dns_openpgpkey_rd_t *)rd;

      r->pubkey_len = *data_len;

      if (!alloc_bytes(data, data_len, &r->pubkey, *data_len))
        return false;

      break;
    }
    case HSK_DNS_OPT: {
      hsk_dns_opt_rd_t *r = (hsk_dns_opt_rd_t *)rd;

      r->rd_len = *data_len;

      if (!alloc_bytes(data, data_len, &r->rd, *data_len))
        return false;

      break;
    }
    case HSK_DNS_DNSKEY: {
      hsk_dns_dnskey_rd_t *r = (hsk_dns_dnskey_rd_t *)rd;

      if (!read_u16be(data, data_len, &r->flags))
        return false;

      if (!read_u8(data, data_len, &r->protocol))
        return false;

      if (!read_u8(data, data_len, &r->algorithm))
        return false;

      r->pubkey_len = *data_len;

      if (!alloc_bytes(data, data_len, &r->pubkey, *data_len))
        return false;

      break;
    }
    case HSK_DNS_RRSIG: {
      hsk_dns_rrsig_rd_t *r = (hsk_dns_rrsig_rd_t *)rd;

      if (!read_u16be(data, data_len, &r->type_covered))
        return false;

      if (!read_u8(data, data_len, &r->algorithm))
        return false;

      if (!read_u8(data, data_len, &r->labels))
        return false;

      if (!read_u32be(data, data_len, &r->orig_ttl))
        return false;

      if (!read_u32be(data, data_len, &r->expiration))
        return false;

      if (!read_u32be(data, data_len, &r->inception))
        return false;

      if (!read_u16be(data, data_len, &r->key_tag))
        return false;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->signer_name))
        return false;

      r->signature_len = *data_len;

      if (!alloc_bytes(data, data_len, &r->signature, *data_len))
        return false;

      break;
    }
    case HSK_DNS_URI: {
      hsk_dns_uri_rd_t *r = (hsk_dns_uri_rd_t *)rd;

      if (!read_u16be(data, data_len, &r->priority))
        return false;

      if (!read_u16be(data, data_len, &r->weight))
        return false;

      if (!read_u8(data, data_len, &r->data_len))
        return false;

      if (!read_bytes(data, data_len, r->data, r->data_len))
        return false;

      break;
    }
    case HSK_DNS_RP: {
      hsk_dns_rp_rd_t *r = (hsk_dns_rp_rd_t *)rd;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->mbox))
        return false;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->txt))
        return false;

      break;
    }
    case HSK_DNS_NSEC: {
      hsk_dns_nsec_rd_t *r = (hsk_dns_nsec_rd_t *)rd;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->next_domain))
        return false;

      r->type_map_len = *data_len;

      if (!alloc_bytes(data, data_len, &r->type_map, *data_len))
        return false;

      break;
    }
    default: {
      hsk_dns_unknown_rd_t *r = (hsk_dns_unknown_rd_t *)rd;

      r->rd_len = *data_len;

      if (!alloc_bytes(data, data_len, &r->rd, *data_len))
        return false;

      break;
    }
  }

  return true;
}

bool
hsk_dns_rd_encode(void *rd, uint16_t type, uint8_t **data, size_t *data_len) {
  if (!rd || !data || !data_len)
    return false;

  size_t size = hsk_dns_rd_size(rd, type);
  uint8_t *raw = malloc(size);

  if (!raw)
    return false;

  uint8_t *d = raw;
  hsk_dns_rd_write(rd, type, &d);

  *data = raw;
  *data_len = size;

  return true;
}

bool
hsk_dns_rd_decode(uint8_t *data, size_t data_len, uint16_t type, void **out) {
  if (!data || !out)
    return false;

  void *rd = hsk_dns_rd_alloc(type);

  if (!rd)
    return false;

  uint8_t *raw = data;
  size_t size = data_len;

  if (!hsk_dns_rd_read(&raw, &size, NULL, 0, rd, type)) {
    hsk_dns_rd_free(rd, type);
    return false;
  }

  *out = rd;

  return true;
}

/*
 * Text
 */

void
hsk_dns_txts_init(hsk_dns_txts_t *txts) {
  assert(txts);
  memset(txts->items, 0, sizeof(hsk_dns_txt_t *) * 255);
  txts->size = 0;
}

void
hsk_dns_txts_uninit(hsk_dns_txts_t *txts) {
  assert(txts);

  int32_t i;
  for (i = 0; i < txts->size; i++) {
    assert(txts->items[i]);
    hsk_dns_txt_free(txts->items[i]);
    txts->items[i] = NULL;
  }

  txts->size = 0;
}

hsk_dns_txts_t *
hsk_dns_txts_alloc(void) {
  hsk_dns_txts_t *txts = malloc(sizeof(hsk_dns_txts_t));
  if (txts)
    hsk_dns_txts_init(txts);
  return txts;
}

void
hsk_dns_txts_free(hsk_dns_txts_t *txts) {
  assert(txts);
  hsk_dns_txts_uninit(txts);
  free(txts);
}

size_t
hsk_dns_txts_unshift(hsk_dns_txts_t *txts, hsk_dns_txt_t *txt) {
  if (txts->size == 255)
    return 0;

  assert(txts->size < 255);

  int32_t i;
  for (i = 1; i < txts->size + 1; i++) {
    assert(txts->items[i - 1]);
    txts->items[i] = txts->items[i - 1];
  }

  txts->items[i] = txt;
  txts->size += 1;

  return txts->size;
}

hsk_dns_txt_t *
hsk_dns_txts_shift(hsk_dns_txts_t *txts) {
  if (txts->size == 0)
    return NULL;

  hsk_dns_txt_t *txt = txts->items[0];

  int32_t i;
  for (i = 0; i < txts->size - 1; i++) {
    assert(txts->items[i]);
    txts->items[i] = txts->items[i + 1];
  }

  txts->items[txts->size - 1] = NULL;

  txts->size -= 1;

  return txt;
}

size_t
hsk_dns_txts_push(hsk_dns_txts_t *txts, hsk_dns_txt_t *txt) {
  if (txts->size == 255)
    return 0;

  assert(txts->size < 255);

  assert(!txts->items[txts->size]);
  txts->items[txts->size] = txt;
  txts->size += 1;

  return txts->size;
}

hsk_dns_txt_t *
hsk_dns_txts_pop(hsk_dns_txts_t *txts) {
  if (txts->size == 0)
    return NULL;

  hsk_dns_txt_t *txt = txts->items[txts->size - 1];
  assert(txt);

  txts->items[txts->size - 1] = NULL;

  txts->size -= 1;

  return txt;
}

hsk_dns_txt_t *
hsk_dns_txts_get(hsk_dns_txts_t *txts, int32_t index) {
  assert(txts);

  if (index < 0)
    index += txts->size;

  if (index >= txts->size)
    return NULL;

  return txts->items[index];
}

size_t
hsk_dns_txts_set(hsk_dns_txts_t *txts, int32_t index, hsk_dns_txt_t *txt) {
  assert(txts && txt);

  if (index < 0)
    index += txts->size;

  if (index >= txts->size)
    return 0;

  txts->items[index] = txt;

  return txts->size;
}

/*
 * Text
 */

void
hsk_dns_txt_init(hsk_dns_txt_t *txt) {
  assert(txt);
  txt->data_len = 0;
  memset(txt->data, 0, sizeof(txt->data));
}

void
hsk_dns_txt_uninit(hsk_dns_txt_t *txt) {
  assert(txt);
}

hsk_dns_txt_t *
hsk_dns_txt_alloc(void) {
  hsk_dns_txt_t *txt = malloc(sizeof(hsk_dns_txt_t));
  if (txt)
    hsk_dns_txt_init(txt);
  return txt;
}

void
hsk_dns_txt_free(hsk_dns_txt_t *txt) {
  assert(txt);
  hsk_dns_txt_uninit(txt);
  free(txt);
}

/*
 * Utils
 */

hsk_dns_rr_t *
hsk_dns_get_rr2(
  hsk_dns_rrs_t *rrs,
  char *target,
  uint8_t type,
  int32_t *index
) {
  char *glue = target;

  int32_t i = 0;

  if (index)
    i = *index;

  for (; i < rrs->size; i++) {
    hsk_dns_rr_t *rr = rrs->items[i];

    if (!target) {
      if (rr->type == type || type == HSK_DNS_ANY) {
        if (index)
          *index = i;
        return rr;
      }
      continue;
    }

    if (rr->type == HSK_DNS_CNAME) {
      if (hsk_dns_name_cmp(rr->name, glue) == 0) {
        if (type == HSK_DNS_CNAME || type == HSK_DNS_ANY) {
          if (index)
            *index = i;
          return rr;
        }

        glue = ((hsk_dns_cname_rd_t *)rr->rd)->target;
      }
      continue;
    }

    if (rr->type == type || type == HSK_DNS_ANY) {
      if (hsk_dns_name_cmp(rr->name, glue) == 0) {
        if (index)
          *index = i;
        return rr;
      }
      continue;
    }
  }

  if (index)
    *index = -1;

  return NULL;
}

hsk_dns_rr_t *
hsk_dns_get_rr(hsk_dns_rrs_t *rrs, char *target, uint8_t type) {
  return hsk_dns_get_rr2(rrs, target, type, NULL);
}

/*
 * Names
 */

int32_t
hsk_dns_name_parse(
  uint8_t **data_,
  size_t *data_len_,
  uint8_t *pd,
  size_t pd_len,
  char *name
) {
  uint8_t *data = *data_;
  size_t data_len = *data_len_;
  int32_t off = 0;
  int32_t noff = 0;
  int32_t res = 0;
  int32_t max = HSK_DNS_MAX_NAME;
  int32_t ptr = 0;

  for (;;) {
    if (off >= data_len)
      return -1;

    uint8_t c = data[off];
    off += 1;

    if (c == 0x00)
      break;

    switch (c & 0xc0) {
      case 0x00: {
        if (c > HSK_DNS_MAX_LABEL)
          return -1;

        if (off + c > data_len)
          return -1; // EOF

        if (noff + c + 1 > max)
          return -1;

        int32_t j;
        for (j = off; j < off + c; j++) {
          uint8_t b = data[j];

          if (b == 0x00)
            b = 0xff;

          // if (b < 0x20 || b > 0x7e)
          //   return -1;

          if (name)
            name[noff] = b;

          noff += 1;
        }

        if (name)
          name[noff] = '.';

        noff += 1;
        off += c;

        break;
      }

      case 0xc0: {
        if (!pd)
          return -1;

        if (off >= data_len)
          return -1;

        uint8_t c1 = data[off];

        off += 1;

        if (ptr == 0)
          res = off;

        ptr += 1;

        if (ptr > 10)
          return -1;

        off = ((c ^ 0xc0) << 8) | c1;

        data = pd;
        data_len = pd_len;

        break;
      }

      default: {
        return -1;
      }
    }
  }

  if (ptr == 0)
    res = off;

  if (noff == 0) {
    if (name)
      name[noff] = '.';
    noff += 1;
  }

  if (name)
    name[noff] = '\0';

  *data_ += res;
  *data_len_ -= res;

  return noff;
}

static bool
hsk_dns_name_serialize(char *name, uint8_t *data, int32_t *len) {
  int32_t off = 0;
  int32_t begin = 0;
  size_t data_len = 256;
  int32_t size;
  int32_t i;
  char *s;

  for (s = name, i = 0; *s; s++, i++) {
    if (name[i] == '.') {
      if (i > 0 && name[i - 1] == '.') {
        *len = off;
        return false;
      }

      size = i - begin;

      if (size > HSK_DNS_MAX_LABEL) {
        *len = off;
        return false;
      }

      if (data) {
        if (off + 1 + size > data_len) {
          *len = off;
          return false;
        }
        data[off] = size;
      }

      off += 1;

      if (data) {
        int32_t j;
        for (j = begin; j < i; j++) {
          char ch = name[j];

          if (ch == -1)
            ch = 0x00;

          data[off] = ch;
        }
      }

      off += size;

      begin = i + 1;
    }
  }

  if (i > HSK_DNS_MAX_NAME) {
    *len = off;
    return false;
  }

  if (i == 0 || name[i - 1] != '.') {
    *len = off;
    return false;
  }

  if (i == 1 && name[0] == '.') {
    *len = off;
    return off;
  }

  if (data) {
    if (off >= data_len) {
      *len = off;
      return false;
    }
    data[off] = 0;
  }

  off += 1;

  *len = off;

  return off;
}

int32_t
hsk_dns_name_pack(char *name, uint8_t *data) {
  int32_t len;
  if (!hsk_dns_name_serialize(name, data, &len))
    return 0;
  return len;
}

int32_t
hsk_dns_name_write(char *name, uint8_t **data) {
  uint8_t *buf = data ? *data : NULL;
  int32_t len;

  hsk_dns_name_serialize(name, buf, &len);

  *data += len;

  return len;
}

bool
hsk_dns_name_read(
  uint8_t **data,
  size_t *data_len,
  uint8_t *pd,
  size_t pd_len,
  char *name
) {
  return hsk_dns_name_parse(data, data_len, pd, pd_len, name) != -1;
}

int32_t
hsk_dns_name_read_size(
  uint8_t *data,
  size_t data_len,
  uint8_t *pd,
  size_t pd_len
) {
  return hsk_dns_name_parse(&data, &data_len, pd, pd_len, NULL);
}

bool
hsk_dns_name_alloc(
  uint8_t **data,
  size_t *data_len,
  uint8_t *pd,
  size_t pd_len,
  char **name
) {
  int32_t size = hsk_dns_name_read_size(*data, *data_len, pd, pd_len);

  if (size == -1)
    return false;

  char *n = malloc(size + 1);

  if (!n)
    return false;

  assert(hsk_dns_name_read(data, data_len, pd, pd_len, n));

  *name = n;

  return true;
}

bool
hsk_dns_name_dirty(char *name) {
  char *s = name;

  while (*s) {
    uint8_t c = (uint8_t)*s;

    if (c < 0x20 || c > 0x7e)
      return true;

    s += 1;
  }

  return false;
}

void
hsk_dns_name_sanitize(char *name, char *out) {
  char *s = name;
  int32_t off = 0;

  while (*s && off < HSK_DNS_MAX_SANITIZED) {
    uint8_t c = (uint8_t)*s;

    switch (c) {
      case 0x28 /*(*/:
      case 0x29 /*)*/:
      case 0x3b /*;*/:
      case 0x20 /* */:
      case 0x40 /*@*/:
      case 0x22 /*"*/:
      case 0x5c /*\\*/: {
        out[off++] = '\\';
        out[off++] = c;
        break;
      }
      case 0xff: {
        c = 0x00;
        ; // fall through
      }
      default: {
        if (c < 0x20 || c > 0x7e) {
          out[off++] = '\\';
          out[off++] = (c / 100) + 0x30;
          out[off++] = (c / 10) + 0x30;
          out[off++] = (c % 10) + 0x30;
        } else {
          out[off++] = c;
        }
        break;
      }
    }

    s += 1;
  }

  out[off] = '\0';
}

bool
hsk_dns_name_verify(char *name) {
  if (name == NULL)
    return false;

  size_t len = strlen(name);
  char n[HSK_DNS_MAX_NAME + 1];

  if (len == 0 || name[len - 1] != '.') {
    if (len + 1 > HSK_DNS_MAX_NAME)
      return false;

    memcpy(&n[0], name, len);
    name = &n[0];
    name[len + 0] = '.';
    name[len + 1] = '\0';
  }

  return hsk_dns_name_pack(name, NULL) != 0;
}

bool
hsk_dns_name_is_fqdn(char *name) {
  if (name == NULL)
    return false;

  size_t len = strlen(name);

  if (len == 0 || name[len - 1] != '.')
    return false;

  return true;
}

int32_t
hsk_dns_name_cmp(char *a, char *b) {
  if (!a && !b)
    return 0;

  if (!a)
    return -1;

  if (!b)
    return 1;

  size_t alen = strlen(a);
  size_t blen = strlen(b);

  if (alen > 0 && a[alen - 1] == '.')
    alen -= 1;

  if (blen > 0 && b[blen - 1] == '.')
    blen -= 1;

  size_t len = alen < blen ? alen : blen;

  int32_t i;
  for (i = 0; i < len; i++) {
    char ai = a[i];
    char bi = b[i];

    if (ai >= 0x41 && ai <= 0x5a)
      ai |= 0x61 - 0x41;

    if (bi >= 0x41 && bi <= 0x5a)
      bi |= 0x61 - 0x41;

    if (ai < bi)
      return -1;

    if (ai > bi)
      return 1;
  }

  if (alen < blen)
    return -1;

  if (alen > blen)
    return 1;

  return 0;
}

/*
 * Labels
 */

int32_t
hsk_dns_label_split(const char *name, uint8_t *labels, size_t size) {
  char *s = (char *)name;
  bool dot = true;
  int32_t count = 0;
  int32_t i;

  if (!labels)
    size = HSK_DNS_MAX_LABELS;

  for (i = 0; *s && count < size; s++, i++) {
    if (*s == '.') {
      dot = true;
      continue;
    }

    if (dot) {
      if (labels)
        labels[count++] = i;
      dot = false;
      continue;
    }
  }

  return count;
}

int32_t
hsk_dns_label_count(char *name) {
  return hsk_dns_label_split(name, NULL, 0);
}

int32_t
hsk_dns_label_from2(
  char *name,
  uint8_t *labels,
  int32_t count,
  int32_t index,
  char *ret
) {
  if (index < 0)
    index += count;

  if (index >= count) {
    ret[0] = '\0';
    return 0;
  }

  size_t start = (size_t)labels[index];
  size_t end = strlen(name);
  size_t len = end - start;

  if (len == 0 || len > HSK_DNS_MAX_NAME) {
    ret[0] = '\0';
    return 0;
  }

  memcpy(ret, &name[start], len);

  ret[len] = '\0';

  return len;
}

int32_t
hsk_dns_label_from(char *name, int32_t index, char *ret) {
  int32_t count = hsk_dns_label_count(name);

  if (count == 0) {
    ret[0] = '\0';
    return 0;
  }

  uint8_t labels[count];

  assert(hsk_dns_label_split(name, labels, count) == count);

  return hsk_dns_label_from2(name, labels, count, index, ret);
}

int32_t
hsk_dns_label_get2(
  char *name,
  uint8_t *labels,
  int32_t count,
  int32_t index,
  char *ret
) {
  if (index < 0)
    index += count;

  if (index >= count) {
    ret[0] = '\0';
    return 0;
  }

  size_t start = (size_t)labels[index];
  size_t end;

  if (index + 1 >= count) {
    end = strlen(name) - 1;
    if (name[end] != '.')
      end += 1;
  } else {
    end = ((size_t)labels[index + 1]) - 1;
  }

  size_t len = end - start;

  if (len == 0 || len > HSK_DNS_MAX_LABEL) {
    ret[0] = '\0';
    return 0;
  }

  memcpy(ret, &name[start], len);

  ret[len] = '\0';

  return len;
}

int32_t
hsk_dns_label_get(char *name, int32_t index, char *ret) {
  int32_t count = hsk_dns_label_count(name);

  if (count == 0) {
    ret[0] = '\0';
    return 0;
  }

  uint8_t labels[count];

  assert(hsk_dns_label_split(name, labels, count) == count);

  return hsk_dns_label_get2(name, labels, count, index, ret);
}

bool
hsk_dns_label_decode_srv(char *name, char *protocol, char *service) {
  int32_t count = hsk_dns_label_count(name);

  if (count < 3)
    return false;

  uint8_t labels[count];

  assert(hsk_dns_label_split(name, labels, count) == count);

  char label[HSK_DNS_MAX_LABEL + 1];
  int32_t len;

  len = hsk_dns_label_get2(name, labels, count, 1, label);

  if (len < 2)
    return false;

  if (label[0] != '_')
    return false;

  if (protocol) {
    char *s = &label[1];

    while (*s) {
      if (*s >= 'A' && *s <= 'Z')
        *s += ' ';
      s += 1;
    }

    strcpy(protocol, &label[1]);
  }

  len = hsk_dns_label_get2(name, labels, count, 0, label);

  if (len < 2)
    return false;

  if (label[0] != '_')
    return false;

  if (service) {
    char *s = &label[1];

    while (*s) {
      if (*s >= 'A' && *s <= 'Z')
        *s += ' ';
      s += 1;
    }

    strcpy(service, &label[1]);
  }

  return true;
}

bool
hsk_dns_label_is_srv(char *name) {
  return hsk_dns_label_decode_srv(name, NULL, NULL);
}

bool
hsk_dns_label_decode_tlsa(char *name, char *protocol, uint16_t *port) {
  int32_t count = hsk_dns_label_count(name);

  if (count < 3)
    return false;

  uint8_t labels[count];

  assert(hsk_dns_label_split(name, labels, count) == count);

  char label[HSK_DNS_MAX_LABEL + 1];
  int32_t len;

  len = hsk_dns_label_get2(name, labels, count, 1, label);

  if (len < 2)
    return false;

  if (label[0] != '_')
    return false;

  if (protocol) {
    char *s = &label[1];

    while (*s) {
      if (*s >= 'A' && *s <= 'Z')
        *s += ' ';
      s += 1;
    }

    strcpy(protocol, &label[1]);
  }

  len = hsk_dns_label_get2(name, labels, count, 0, label);

  if (len < 2 || len > 6)
    return false;

  if (label[0] != '_')
    return false;

  uint32_t word = 0;
  char *s = &label[1];

  while (*s) {
    int32_t ch = ((int32_t)*s) - 0x30;

    if (ch < 0 || ch > 9)
      return false;

    word *= 10;
    word += ch;

    if (word > 0xffff)
      return false;
  }

  if (port)
    *port = (uint16_t)word;

  return true;
}

bool
hsk_dns_label_is_tlsa(char *name) {
  return hsk_dns_label_decode_tlsa(name, NULL, NULL);
}

bool
hsk_dns_label_decode_smimea(char *name, uint8_t *hash) {
  int32_t count = hsk_dns_label_count(name);

  if (count < 3)
    return false;

  uint8_t labels[count];

  assert(hsk_dns_label_split(name, labels, count) == count);

  char label[HSK_DNS_MAX_LABEL + 1];
  int32_t len;

  len = hsk_dns_label_get2(name, labels, count, 1, label);

  if (len != 7)
    return false;

  if (strcasecmp(label, "_smimea") != 0)
    return false;

  len = hsk_dns_label_get2(name, labels, count, 0, label);

  if (len != 57)
    return false;

  if (label[0] != '_')
    return false;

  if (!hsk_hex_decode(&label[1], hash))
    return false;

  return true;
}

bool
hsk_dns_label_is_smimea(char *name) {
  return hsk_dns_label_decode_smimea(name, NULL);
}

/*
 * Iterator
 */

void
hsk_dns_iter_init(
  hsk_dns_iter_t *it,
  hsk_dns_rrs_t *rrs,
  char *target,
  uint8_t type
) {
  it->rrs = rrs;
  it->target = target;
  it->type = type;
  it->index = 0;
}

hsk_dns_rr_t *
hsk_dns_iter_next(hsk_dns_iter_t *it) {
  if (it->index == -1)
    return NULL;

  hsk_dns_rr_t *rr = hsk_dns_get_rr2(it->rrs, it->target, it->type, &it->index);

  if (!rr) {
    it->index = -1;
    return NULL;
  }

  if (it->target)
    it->target = rr->name;

  it->index += 1;

  return rr;
}

/*
 * DNSSEC
 */

int32_t
hsk_dns_dnskey_keytag(hsk_dns_dnskey_rd_t *rd) {
  uint8_t *data;
  size_t size;

  if (!hsk_dns_rd_encode(rd, HSK_DNS_DNSKEY, &data, &size))
    return -1;

  uint32_t tag = 0;
  size_t i;

  for (i = 0; i < size; i++) {
    uint8_t ch = data[i];

    if (i & 1)
      tag += ch;
    else
      tag += ch << 8;
  }

  tag += (tag >> 16) & 0xffff;
  tag &= 0xffff;

  free(data);

  return tag;
}

bool
hsk_dns_rrsig_tbs(hsk_dns_rrsig_rd_t *rrsig, uint8_t **data, size_t *data_len) {
  char signer_name[HSK_DNS_MAX_NAME + 1];
  strcpy(signer_name, rrsig->signer_name);

  uint8_t *signature = rrsig->signature;
  size_t signature_len = rrsig->signature_len;

  to_lower(rrsig->signer_name);
  rrsig->signature = NULL;
  rrsig->signature_len = 0;

  bool ret = hsk_dns_rd_encode(rrsig, HSK_DNS_RRSIG, data, data_len);

  strcpy(rrsig->signer_name, signer_name);
  rrsig->signature = signature;
  rrsig->signature_len = signature_len;

  return ret;
}

hsk_dns_rr_t *
hsk_dns_dnskey_create(char *zone, uint8_t *priv, bool ksk) {
  hsk_dns_rr_t *key = hsk_dns_rr_alloc();

  if (!key)
    return NULL;

  hsk_dns_dnskey_rd_t *dnskey = hsk_dns_rd_alloc(HSK_DNS_DNSKEY);

  if (!dnskey) {
    hsk_dns_rr_free(key);
    return NULL;
  }

  uint8_t *pubkey = malloc(64);

  if (!pubkey) {
    hsk_dns_rr_free(key);
    return NULL;
  }

  if (!ecc_make_pubkey(priv, pubkey)) {
    hsk_dns_rr_free(key);
    return NULL;
  }

  strcpy(key->name, zone);
  to_lower(key->name);
  key->type = HSK_DNS_DNSKEY;
  key->class = HSK_DNS_IN;
  key->ttl = 10800;
  key->rd = dnskey;

  dnskey->flags = (1 << 8) | (ksk ? 1 : 0);
  dnskey->protocol = 3;
  dnskey->algorithm = 13; // ECDSAP256SHA256
  dnskey->pubkey_len = 64;
  dnskey->pubkey = pubkey;

  return key;
}

hsk_dns_rr_t *
hsk_dns_ds_create(hsk_dns_rr_t *key) {
  if (!key || key->type != HSK_DNS_DNSKEY)
    return NULL;

  hsk_dns_dnskey_rd_t *dnskey = (hsk_dns_dnskey_rd_t *)key->rd;

  hsk_dns_rr_t *ds = hsk_dns_rr_alloc();

  if (!ds)
    return NULL;

  hsk_dns_ds_rd_t *dsrd = hsk_dns_rd_alloc(HSK_DNS_DS);

  if (!dsrd) {
    hsk_dns_rr_free(ds);
    return NULL;
  }

  int32_t key_tag = hsk_dns_dnskey_keytag(dnskey);

  if (key_tag == -1) {
    hsk_dns_rr_free(ds);
    return NULL;
  }

  uint8_t *digest = malloc(32);

  if (!digest) {
    hsk_dns_rr_free(ds);
    return NULL;
  }

  strcpy(ds->name, key->name);
  to_lower(ds->name);
  ds->type = HSK_DNS_DS;
  ds->class = key->class;
  ds->ttl = key->ttl;
  ds->rd = dsrd;

  dsrd->key_tag = key_tag;
  dsrd->algorithm = dnskey->algorithm;
  dsrd->digest_type = 2; // SHA256
  dsrd->digest_len = 32;
  dsrd->digest = digest;

  uint8_t *data;
  size_t size;

  if (!hsk_dns_rd_encode(dnskey, HSK_DNS_DNSKEY, &data, &size)) {
    hsk_dns_rr_free(ds);
    return NULL;
  }

  uint8_t owner[HSK_DNS_MAX_NAME + 1];
  size_t owner_len = hsk_dns_name_pack(ds->name, owner);

  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, owner, owner_len);
  sha256_update(&ctx, data, size);
  sha256_final(&ctx, digest);

  free(data);

  return ds;
}

hsk_dns_rr_t *
hsk_dns_sign_rrset(hsk_dns_rrs_t *rrset, hsk_dns_rr_t *key, uint8_t *priv) {
  if (!rrset || !key || !priv)
    return NULL;

  if (rrset->size == 0)
    return NULL;

  if (key->type != HSK_DNS_DNSKEY)
    return NULL;

  hsk_dns_dnskey_rd_t *dnskey = (hsk_dns_dnskey_rd_t *)key->rd;

  hsk_dns_rr_t *sig = hsk_dns_rr_alloc();

  if (!sig)
    return NULL;

  hsk_dns_rrsig_rd_t *rrsig = hsk_dns_rd_alloc(HSK_DNS_RRSIG);

  if (!rrsig) {
    hsk_dns_rr_free(sig);
    return NULL;
  }

  int32_t key_tag = hsk_dns_dnskey_keytag(dnskey);

  if (key_tag == -1) {
    hsk_dns_rr_free(sig);
    return NULL;
  }

  strcpy(sig->name, key->name);
  to_lower(sig->name);
  sig->type = HSK_DNS_RRSIG;
  sig->class = key->class;
  sig->ttl = key->ttl;
  sig->rd = rrsig;

  rrsig->key_tag = key_tag;
  strcpy(rrsig->signer_name, key->name);
  to_lower(rrsig->signer_name);
  rrsig->algorithm = dnskey->algorithm;
  rrsig->inception = hsk_now() - (14 * 24 * 60 * 60);
  rrsig->expiration = hsk_now() + (14 * 24 * 60 * 60);

  if (!hsk_dns_sign_rrsig(rrset, sig, priv)) {
    hsk_dns_rr_free(sig);
    return NULL;
  }

  return sig;
}

bool
hsk_dns_sign_rrsig(hsk_dns_rrs_t *rrset, hsk_dns_rr_t *sig, uint8_t *priv) {
  if (!rrset || rrset->size == 0)
    return false;

  if (!sig || sig->type != HSK_DNS_RRSIG)
    return false;

  if (!priv)
    return false;

  uint8_t *sigbuf = malloc(64);

  if (!sigbuf)
    return false;

  hsk_dns_rrsig_rd_t *rrsig = (hsk_dns_rrsig_rd_t *)sig->rd;

  rrsig->orig_ttl = rrset->items[0]->ttl;
  rrsig->type_covered = rrset->items[0]->type;
  rrsig->labels = hsk_dns_label_count(rrset->items[0]->name);
  rrsig->signature_len = 0;
  rrsig->signature = NULL;

  uint8_t hash[32];

  if (!hsk_dns_sighash(rrset, sig, hash)) {
    free(sigbuf);
    return false;
  }

  if (!hsk_dns_sign_sig(priv, hash, sigbuf)) {
    free(sigbuf);
    return false;
  }

  rrsig->signature_len = 64;
  rrsig->signature = sigbuf;

  return true;
}

bool
hsk_dns_sign_sig(uint8_t *priv, uint8_t *hash, uint8_t *sigbuf) {
  if (!ecdsa_sign(priv, hash, sigbuf))
    return false;
  return true;
}

bool
hsk_dns_sighash(hsk_dns_rrs_t *rrset, hsk_dns_rr_t *sig, uint8_t *hash) {
  if (!rrset || rrset->size == 0)
    return false;

  if (!sig || sig->type != HSK_DNS_RRSIG)
    return false;

  if (!hash)
    return false;

  hsk_dns_rrsig_rd_t *rrsig = (hsk_dns_rrsig_rd_t *)sig->rd;

  hsk_dns_raw_rr_t *records =
    calloc(rrset->size, sizeof(hsk_dns_raw_rr_t));

  if (!records)
    return false;

  int32_t i, j;
  uint8_t *data;
  size_t size;
  bool ret = true;

  for (i = 0; i < rrset->size; i++) {
    hsk_dns_rr_t *item = rrset->items[i];
    hsk_dns_rr_t *rr = hsk_dns_rr_clone(item);

    if (!rr)
      goto fail;

    to_lower(rr->name);

    rr->ttl = rrsig->orig_ttl;

    switch (rr->type) {
      case HSK_DNS_NS:
        to_lower(((hsk_dns_ns_rd_t *)rr->rd)->ns);
        break;
      case HSK_DNS_CNAME:
        to_lower(((hsk_dns_cname_rd_t *)rr->rd)->target);
        break;
      case HSK_DNS_SOA:
        to_lower(((hsk_dns_soa_rd_t *)rr->rd)->ns);
        to_lower(((hsk_dns_soa_rd_t *)rr->rd)->mbox);
        break;
      case HSK_DNS_PTR:
        to_lower(((hsk_dns_ptr_rd_t *)rr->rd)->ptr);
        break;
      case HSK_DNS_MX:
        to_lower(((hsk_dns_mx_rd_t *)rr->rd)->mx);
        break;
      case HSK_DNS_SIG:
      case HSK_DNS_RRSIG:
        to_lower(((hsk_dns_rrsig_rd_t *)rr->rd)->signer_name);
        break;
      case HSK_DNS_SRV:
        to_lower(((hsk_dns_srv_rd_t *)rr->rd)->target);
        break;
      case HSK_DNS_DNAME:
        to_lower(((hsk_dns_dname_rd_t *)rr->rd)->target);
        break;
    }

    if (!hsk_dns_rr_encode(rr, &data, &size)) {
      hsk_dns_rr_free(rr);
      goto fail;
    }

    hsk_dns_rr_free(rr);

    hsk_dns_raw_rr_t *rec = &records[i];

    rec->size = size;
    rec->data = data;
  }

  qsort((void *)records, rrset->size, sizeof(hsk_dns_raw_rr_t), raw_rr_cmp);

  if (!hsk_dns_rrsig_tbs(rrsig, &data, &size))
    goto fail;

  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, size);

  free(data);

  hsk_dns_raw_rr_t *last = NULL;

  for (j = 0; i < rrset->size; j++) {
    hsk_dns_raw_rr_t *item = &records[j];

    if (last && raw_rr_equal(item, last))
      continue;

    sha256_update(&ctx, item->data, item->size);

    last = item;
  }

  sha256_final(&ctx, hash);

  goto done;

fail:
  ret = false;

done:
  for (j = 0; j < i; j++) {
    hsk_dns_raw_rr_t *item = &records[i];

    if (item->data)
      free(item->data);
  }

  free(records);

  return ret;
}

/*
 * Helpers
 */

static void
to_lower(char *name) {
  assert(name);

  char *s = name;

  while (*s) {
    if (*s >= 'A' && *s <= 'Z')
      *s += ' ';
    s += 1;
  }
}

static int32_t
raw_rr_cmp(const void *a, const void *b) {
  assert(a && b);

  hsk_dns_raw_rr_t *x = (hsk_dns_raw_rr_t *)a;
  hsk_dns_raw_rr_t *y = (hsk_dns_raw_rr_t *)b;

  uint8_t *xd = x->data;
  size_t xs = x->size;
  uint8_t *yd = y->data;
  size_t ys = y->size;

  assert(hsk_dns_name_parse(&xd, &xs, NULL, 0, NULL) != -1);
  assert(hsk_dns_name_parse(&yd, &ys, NULL, 0, NULL) != -1);

  assert(xs >= 10);
  assert(ys >= 10);

  xd += 10;
  xs -= 10;
  yd += 10;
  ys -= 10;

  size_t s = xs < ys ? xs : ys;

  int32_t r = memcmp(xd, yd, s);

  if (r != 0)
    return r;

  if (xs < ys)
    return -1;

  if (xs > ys)
    return 1;

  return 0;
}

static bool
raw_rr_equal(hsk_dns_raw_rr_t *a, hsk_dns_raw_rr_t *b) {
  assert(a && b);

  if (a->size != b->size)
    return false;

  return memcmp(a->data, b->data, a->size) == 0;
}
