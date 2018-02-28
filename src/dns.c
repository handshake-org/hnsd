#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>

#include "bio.h"
#include "dns.h"

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
  msg->edns.ttl = 0;
  msg->edns.size = 0;
  msg->edns.code = 0;
  msg->edns.flags = 0;
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

  if (!hsk_dns_msg_read(&data, &data_len, m))
    return false;

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
  flags |= ((uint16_t)msg->code) & 0x0f;

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

  if (msg->edns.enabled) {
    hsk_dns_opt_rr_t opt = { .type = HSK_DNS_OPT };
    strcpy(opt.name, ".");
    opt.ttl = 0;
    opt.ttl |= ((uint32_t)msg->edns.code) << 24;
    opt.ttl |= ((uint32_t)msg->edns.version) << 16;
    opt.ttl |= (uint32_t)msg->edns.ttl;
    opt.class = msg->edns.size;
    opt.rd_len = msg->edns.rd_len;
    opt.rd = msg->edns.rd;
    size += hsk_dns_rr_write((hsk_dns_rr_t *)&opt, data);
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

    hsk_dns_rr_t *rr = hsk_dns_rr_alloc(HSK_DNS_ANY);

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

    hsk_dns_rr_t *rr = hsk_dns_rr_alloc(HSK_DNS_ANY);

    if (!rr)
      goto fail;

    if (!hsk_dns_rr_read(data, data_len, pd, pd_len, rr))
      goto fail;

    hsk_dns_rrs_push(&msg->ns, rr);
  }

  for (i = 0; i < arcount; i++) {
    if (*data_len == 0)
      break;

    hsk_dns_rr_t *rr = hsk_dns_rr_alloc(HSK_DNS_ANY);

    if (!rr)
      goto fail;

    if (!hsk_dns_rr_read(data, data_len, pd, pd_len, rr))
      goto fail;

    if (rr->type == HSK_DNS_OPT) {
      hsk_dns_opt_rr_t *opt = (hsk_dns_opt_rr_t *)rr;

      if (msg->edns.enabled) {
        free(rr);
        continue;
      }

      msg->edns.enabled = true;
      msg->edns.code = (opt->ttl >> 24) & 0xff;
      msg->edns.version = (opt->ttl >> 16) & 0xff;
      msg->edns.ttl = opt->ttl & 0xffff;
      msg->edns.size = opt->class;
      msg->edns.rd_len = opt->rd_len;
      msg->edns.rd = opt->rd;

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

void
hsk_dns_qs_init(hsk_dns_qs_t *qs) {
  assert(qs);

  memset(qs->name, 0, sizeof(qs->name));
  qs->type = 0;
  qs->class = 0;
  qs->ttl = 0;
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

void
hsk_dns_rr_init(hsk_dns_rr_t *rr, uint16_t type) {
  assert(rr);

  memset(rr->name, 0, sizeof(rr->name));
  rr->type = type;
  rr->class = 0;
  rr->ttl = 0;

  hsk_dns_rd_init(rr);
}

void
hsk_dns_rd_init(hsk_dns_rr_t *rr) {
  switch (rr->type) {
    case HSK_DNS_SOA: {
      hsk_dns_soa_rr_t *r = (hsk_dns_soa_rr_t *)rr;
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
      hsk_dns_a_rr_t *r = (hsk_dns_a_rr_t *)rr;
      memset(r->addr, 0, 4);
      break;
    }
    case HSK_DNS_AAAA: {
      hsk_dns_aaaa_rr_t *r = (hsk_dns_aaaa_rr_t *)rr;
      memset(r->addr, 0, 16);
      break;
    }
    case HSK_DNS_CNAME: {
      hsk_dns_cname_rr_t *r = (hsk_dns_cname_rr_t *)rr;
      memset(r->target, 0, sizeof(r->target));
      break;
    }
    case HSK_DNS_DNAME: {
      hsk_dns_dname_rr_t *r = (hsk_dns_dname_rr_t *)rr;
      memset(r->target, 0, sizeof(r->target));
      break;
    }
    case HSK_DNS_NS: {
      hsk_dns_ns_rr_t *r = (hsk_dns_ns_rr_t *)rr;
      memset(r->ns, 0, sizeof(r->ns));
      break;
    }
    case HSK_DNS_MX: {
      hsk_dns_mx_rr_t *r = (hsk_dns_mx_rr_t *)rr;
      r->preference = 0;
      memset(r->mx, 0, sizeof(r->mx));
      break;
    }
    case HSK_DNS_PTR: {
      hsk_dns_ptr_rr_t *r = (hsk_dns_ptr_rr_t *)rr;
      memset(r->ptr, 0, sizeof(r->ptr));
      break;
    }
    case HSK_DNS_SRV: {
      hsk_dns_srv_rr_t *r = (hsk_dns_srv_rr_t *)rr;
      r->priority = 0;
      r->weight = 0;
      r->port = 0;
      memset(r->target, 0, sizeof(r->target));
      break;
    }
    case HSK_DNS_TXT: {
      hsk_dns_txt_rr_t *r = (hsk_dns_txt_rr_t *)rr;
      hsk_dns_txts_init(&r->txts);
      break;
    }
    case HSK_DNS_DS: {
      hsk_dns_ds_rr_t *r = (hsk_dns_ds_rr_t *)rr;
      r->key_tag = 0;
      r->algorithm = 0;
      r->digest_type = 0;
      r->digest_len = 0;
      r->digest = NULL;
      break;
    }
    case HSK_DNS_TLSA: {
      hsk_dns_tlsa_rr_t *r = (hsk_dns_tlsa_rr_t *)rr;
      r->usage = 0;
      r->selector = 0;
      r->matching_type = 0;
      r->certificate_len = 0;
      r->certificate = NULL;
      break;
    }
    case HSK_DNS_SSHFP: {
      hsk_dns_sshfp_rr_t *r = (hsk_dns_sshfp_rr_t *)rr;
      r->algorithm = 0;
      r->key_type = 0;
      r->fingerprint_len = 0;
      r->fingerprint = NULL;
      break;
    }
    case HSK_DNS_OPT: {
      hsk_dns_opt_rr_t *r = (hsk_dns_opt_rr_t *)rr;
      r->rd_len = 0;
      r->rd = NULL;
      break;
    }
    case HSK_DNS_DNSKEY: {
      hsk_dns_dnskey_rr_t *r = (hsk_dns_dnskey_rr_t *)rr;
      r->flags = 0;
      r->protocol = 0;
      r->algorithm = 0;
      r->public_key_len = 0;
      r->public_key = NULL;
      break;
    }
    case HSK_DNS_RRSIG: {
      hsk_dns_rrsig_rr_t *r = (hsk_dns_rrsig_rr_t *)rr;
      r->type_covered = 0;
      r->algorithm = 0;
      r->labels = 0;
      r->orig_ttl = 0;
      r->expiration = 0;
      r->inception = 0;
      r->key_tag = 0;
      memcpy(r->signer_name, 0, sizeof(r->signer_name));
      r->signature_len = 0;
      r->signature = NULL;
      break;
    }
    case HSK_DNS_URI: {
      hsk_dns_uri_rr_t *r = (hsk_dns_uri_rr_t *)rr;
      r->priority = 0;
      r->weight = 0;
      r->data_len = 0;
      memset(r->data, 0, sizeof(r->data));
      break;
    }
    case HSK_DNS_RP: {
      hsk_dns_rp_rr_t *r = (hsk_dns_rp_rr_t *)rr;
      memset(r->mbox, 0, sizeof(r->mbox));
      memset(r->txt, 0, sizeof(r->txt));
      break;
    }
    default: {
      hsk_dns_unknown_rr_t *r = (hsk_dns_unknown_rr_t *)rr;
      r->rd_len = 0;
      r->rd = NULL;
      break;
    }
  }
}

hsk_dns_rr_t *
hsk_dns_rr_alloc(uint16_t type) {
  hsk_dns_rr_t *rr;

  switch (type) {
    case HSK_DNS_ANY: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_any_rr_t));
      break;
    }
    case HSK_DNS_SOA: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_soa_rr_t));
      break;
    }
    case HSK_DNS_A: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_a_rr_t));
      break;
    }
    case HSK_DNS_AAAA: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_aaaa_rr_t));
      break;
    }
    case HSK_DNS_CNAME: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_cname_rr_t));
      break;
    }
    case HSK_DNS_DNAME: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_dname_rr_t));
      break;
    }
    case HSK_DNS_NS: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_ns_rr_t));
      break;
    }
    case HSK_DNS_MX: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_mx_rr_t));
      break;
    }
    case HSK_DNS_PTR: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_ptr_rr_t));
      break;
    }
    case HSK_DNS_SRV: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_srv_rr_t));
      break;
    }
    case HSK_DNS_TXT: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_txt_rr_t));
      break;
    }
    case HSK_DNS_DS: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_ds_rr_t));
      break;
    }
    case HSK_DNS_TLSA: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_tlsa_rr_t));
      break;
    }
    case HSK_DNS_SSHFP: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_sshfp_rr_t));
      break;
    }
    case HSK_DNS_OPT: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_opt_rr_t));
      break;
    }
    case HSK_DNS_DNSKEY: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_dnskey_rr_t));
      break;
    }
    case HSK_DNS_RRSIG: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_rrsig_rr_t));
      break;
    }
    case HSK_DNS_URI: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_uri_rr_t));
      break;
    }
    case HSK_DNS_RP: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_rp_rr_t));
      break;
    }
    default: {
      rr = (hsk_dns_rr_t *)malloc(sizeof(hsk_dns_unknown_rr_t));
      break;
    }
  }

  if (rr)
    hsk_dns_rr_init(rr, type);

  return rr;
}

void
hsk_dns_rr_uninit(hsk_dns_rr_t *rr) {
  assert(rr);

  switch (rr->type) {
    case HSK_DNS_ANY: {
      memset(rr, 0, sizeof(hsk_dns_any_rr_t *));
      break;
    }
    case HSK_DNS_SOA: {
      hsk_dns_soa_rr_t *r = (hsk_dns_soa_rr_t *)rr;
      break;
    }
    case HSK_DNS_A: {
      hsk_dns_a_rr_t *r = (hsk_dns_a_rr_t *)rr;
      break;
    }
    case HSK_DNS_AAAA: {
      hsk_dns_aaaa_rr_t *r = (hsk_dns_aaaa_rr_t *)rr;
      break;
    }
    case HSK_DNS_CNAME: {
      hsk_dns_cname_rr_t *r = (hsk_dns_cname_rr_t *)rr;
      break;
    }
    case HSK_DNS_DNAME: {
      hsk_dns_dname_rr_t *r = (hsk_dns_dname_rr_t *)rr;
      break;
    }
    case HSK_DNS_NS: {
      hsk_dns_ns_rr_t *r = (hsk_dns_ns_rr_t *)rr;
      break;
    }
    case HSK_DNS_MX: {
      hsk_dns_mx_rr_t *r = (hsk_dns_mx_rr_t *)rr;
      break;
    }
    case HSK_DNS_PTR: {
      hsk_dns_ptr_rr_t *r = (hsk_dns_ptr_rr_t *)rr;
      break;
    }
    case HSK_DNS_SRV: {
      hsk_dns_srv_rr_t *r = (hsk_dns_srv_rr_t *)rr;
      break;
    }
    case HSK_DNS_TXT: {
      hsk_dns_txt_rr_t *r = (hsk_dns_txt_rr_t *)rr;
      hsk_dns_txts_uninit(&r->txts);
      break;
    }
    case HSK_DNS_DS: {
      hsk_dns_ds_rr_t *r = (hsk_dns_ds_rr_t *)rr;
      if (r->digest) {
        free(r->digest);
        r->digest = NULL;
      }
      break;
    }
    case HSK_DNS_TLSA: {
      hsk_dns_tlsa_rr_t *r = (hsk_dns_tlsa_rr_t *)rr;
      if (r->certificate) {
        free(r->certificate);
        r->certificate = NULL;
      }
      break;
    }
    case HSK_DNS_SSHFP: {
      hsk_dns_sshfp_rr_t *r = (hsk_dns_sshfp_rr_t *)rr;
      if (r->fingerprint) {
        free(r->fingerprint);
        r->fingerprint = NULL;
      }
      break;
    }
    case HSK_DNS_OPT: {
      hsk_dns_opt_rr_t *r = (hsk_dns_opt_rr_t *)rr;
      if (r->rd) {
        free(r->rd);
        r->rd = NULL;
      }
      break;
    }
    case HSK_DNS_DNSKEY: {
      hsk_dns_dnskey_rr_t *r = (hsk_dns_dnskey_rr_t *)rr;
      if (r->public_key) {
        free(r->public_key);
        r->public_key = NULL;
      }
      break;
    }
    case HSK_DNS_RRSIG: {
      hsk_dns_rrsig_rr_t *r = (hsk_dns_rrsig_rr_t *)rr;
      if (r->signature) {
        free(r->signature);
        r->signature = NULL;
      }
      break;
    }
    case HSK_DNS_URI: {
      hsk_dns_uri_rr_t *r = (hsk_dns_uri_rr_t *)rr;
      break;
    }
    case HSK_DNS_RP: {
      hsk_dns_rp_rr_t *r = (hsk_dns_rp_rr_t *)rr;
      break;
    }
    default: {
      hsk_dns_unknown_rr_t *r = (hsk_dns_unknown_rr_t *)rr;
      if (r->rd) {
        free(r->rd);
        r->rd = NULL;
      }
      break;
    }
  }
}

void
hsk_dns_rr_free(hsk_dns_rr_t *rr) {
  assert(rr);
  hsk_dns_rr_uninit(rr);
  free(rr);
}

void
hsk_dns_rr_set_name(hsk_dns_rr_t *rr, char *name) {
  assert(rr && name);
  assert(strlen(name) <= 255);
  strcpy(rr->name, name);
}

int32_t
hsk_dns_rr_write(hsk_dns_rr_t *rr, uint8_t **data) {
  int32_t size = 0;
  size += hsk_dns_name_write(rr->name, data);
  size += write_u16be(data, rr->type);
  size += write_u16be(data, rr->class);
  size += write_u32be(data, rr->ttl);
  size += write_u16be(data, hsk_dns_rd_size(rr));
  size += hsk_dns_rd_write(rr, data);
  return size;
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

  uint8_t *rd = *data;
  size_t rdlen = (size_t)len;

  if (!hsk_dns_rd_read(&rd, &rdlen, pd, pd_len, rr))
    return false;

  *data += len;
  *data_len -= len;

  return true;
}

int32_t
hsk_dns_rd_write(hsk_dns_rr_t *rr, uint8_t **data) {
  int32_t size = 0;

  switch (rr->type) {
    case HSK_DNS_SOA: {
      hsk_dns_soa_rr_t *r = (hsk_dns_soa_rr_t *)rr;

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
      hsk_dns_a_rr_t *r = (hsk_dns_a_rr_t *)rr;

      size += write_bytes(data, r->addr, 4);

      break;
    }
    case HSK_DNS_AAAA: {
      hsk_dns_aaaa_rr_t *r = (hsk_dns_aaaa_rr_t *)rr;

      size += write_bytes(data, r->addr, 16);

      break;
    }
    case HSK_DNS_CNAME: {
      hsk_dns_cname_rr_t *r = (hsk_dns_cname_rr_t *)rr;

      size += hsk_dns_name_write(r->target, data);

      break;
    }
    case HSK_DNS_DNAME: {
      hsk_dns_dname_rr_t *r = (hsk_dns_dname_rr_t *)rr;

      size += hsk_dns_name_write(r->target, data);

      break;
    }
    case HSK_DNS_NS: {
      hsk_dns_ns_rr_t *r = (hsk_dns_ns_rr_t *)rr;

      size += hsk_dns_name_write(r->ns, data);

      break;
    }
    case HSK_DNS_MX: {
      hsk_dns_mx_rr_t *r = (hsk_dns_mx_rr_t *)rr;

      size += write_u16be(data, r->preference);
      size += hsk_dns_name_write(r->mx, data);

      break;
    }
    case HSK_DNS_PTR: {
      hsk_dns_ptr_rr_t *r = (hsk_dns_ptr_rr_t *)rr;

      size += hsk_dns_name_write(r->ptr, data);

      break;
    }
    case HSK_DNS_SRV: {
      hsk_dns_srv_rr_t *r = (hsk_dns_srv_rr_t *)rr;

      size += write_u16be(data, r->priority);
      size += write_u16be(data, r->weight);
      size += write_u16be(data, r->port);
      size += hsk_dns_name_write(r->target, data);

      break;
    }
    case HSK_DNS_TXT: {
      hsk_dns_txt_rr_t *r = (hsk_dns_txt_rr_t *)rr;

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
      hsk_dns_ds_rr_t *r = (hsk_dns_ds_rr_t *)rr;

      size += write_u16be(data, r->key_tag);
      size += write_u8(data, r->algorithm);
      size += write_u8(data, r->digest_type);
      size += write_bytes(data, r->digest, r->digest_len);

      break;
    }
    case HSK_DNS_TLSA: {
      hsk_dns_tlsa_rr_t *r = (hsk_dns_tlsa_rr_t *)rr;

      size += write_u8(data, r->usage);
      size += write_u8(data, r->selector);
      size += write_u8(data, r->matching_type);
      size += write_bytes(data, r->certificate, r->certificate_len);

      break;
    }
    case HSK_DNS_SSHFP: {
      hsk_dns_sshfp_rr_t *r = (hsk_dns_sshfp_rr_t *)rr;

      size += write_u8(data, r->algorithm);
      size += write_u8(data, r->key_type);
      size += write_bytes(data, r->fingerprint, r->fingerprint_len);

      break;
    }
    case HSK_DNS_OPT: {
      hsk_dns_opt_rr_t *r = (hsk_dns_opt_rr_t *)rr;

      size += write_bytes(data, r->rd, r->rd_len);

      break;
    }
    case HSK_DNS_DNSKEY: {
      hsk_dns_dnskey_rr_t *r = (hsk_dns_dnskey_rr_t *)rr;

      size += write_u16be(data, r->flags);
      size += write_u8(data, r->protocol);
      size += write_u8(data, r->algorithm);
      size += write_u8(data, r->public_key_len);
      size += write_bytes(data, r->public_key, r->public_key_len);

      break;
    }
    case HSK_DNS_RRSIG: {
      hsk_dns_rrsig_rr_t *r = (hsk_dns_rrsig_rr_t *)rr;

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
      hsk_dns_uri_rr_t *r = (hsk_dns_uri_rr_t *)rr;

      size += write_u16be(data, r->priority);
      size += write_u16be(data, r->weight);
      size += write_u8(data, r->data_len);
      size += write_bytes(data, r->data, r->data_len);

      break;
    }
    case HSK_DNS_RP: {
      hsk_dns_rp_rr_t *r = (hsk_dns_rp_rr_t *)rr;

      size += hsk_dns_name_write(r->mbox, data);
      size += hsk_dns_name_write(r->txt, data);

      break;
    }
    default: {
      hsk_dns_unknown_rr_t *r = (hsk_dns_unknown_rr_t *)rr;

      size += write_bytes(data, r->rd, r->rd_len);

      break;
    }
  }

  return size;
}

int32_t
hsk_dns_rd_size(hsk_dns_rr_t *rr) {
  return hsk_dns_rd_write(rr, NULL);
}

bool
hsk_dns_rd_read(
  uint8_t **data,
  size_t *data_len,
  uint8_t *pd,
  size_t pd_len,
  hsk_dns_rr_t *rr
) {
  switch (rr->type) {
    case HSK_DNS_SOA: {
      hsk_dns_soa_rr_t *r = (hsk_dns_soa_rr_t *)rr;

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
      hsk_dns_a_rr_t *r = (hsk_dns_a_rr_t *)rr;

      if (!read_bytes(data, data_len, r->addr, 4))
        return false;

      break;
    }
    case HSK_DNS_AAAA: {
      hsk_dns_aaaa_rr_t *r = (hsk_dns_aaaa_rr_t *)rr;

      if (!read_bytes(data, data_len, r->addr, 16))
        return false;

      break;
    }
    case HSK_DNS_CNAME: {
      hsk_dns_cname_rr_t *r = (hsk_dns_cname_rr_t *)rr;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->target))
        return false;

      break;
    }
    case HSK_DNS_DNAME: {
      hsk_dns_dname_rr_t *r = (hsk_dns_dname_rr_t *)rr;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->target))
        return false;

      break;
    }
    case HSK_DNS_NS: {
      hsk_dns_ns_rr_t *r = (hsk_dns_ns_rr_t *)rr;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->ns))
        return false;

      break;
    }
    case HSK_DNS_MX: {
      hsk_dns_mx_rr_t *r = (hsk_dns_mx_rr_t *)rr;

      if (!read_u16be(data, data_len, &r->preference))
        return false;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->mx))
        return false;

      break;
    }
    case HSK_DNS_PTR: {
      hsk_dns_ptr_rr_t *r = (hsk_dns_ptr_rr_t *)rr;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->ptr))
        return false;

      break;
    }
    case HSK_DNS_SRV: {
      hsk_dns_srv_rr_t *r = (hsk_dns_srv_rr_t *)rr;

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
      hsk_dns_txt_rr_t *r = (hsk_dns_txt_rr_t *)rr;

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
      hsk_dns_ds_rr_t *r = (hsk_dns_ds_rr_t *)rr;

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
      hsk_dns_tlsa_rr_t *r = (hsk_dns_tlsa_rr_t *)rr;

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
      hsk_dns_sshfp_rr_t *r = (hsk_dns_sshfp_rr_t *)rr;

      if (!read_u8(data, data_len, &r->algorithm))
        return false;

      if (!read_u8(data, data_len, &r->key_type))
        return false;

      r->fingerprint_len = *data_len;

      if (!alloc_bytes(data, data_len, &r->fingerprint, *data_len))
        return false;

      break;
    }
    case HSK_DNS_OPT: {
      hsk_dns_opt_rr_t *r = (hsk_dns_opt_rr_t *)rr;

      r->rd_len = *data_len;

      if (!alloc_bytes(data, data_len, &r->rd, *data_len))
        return false;

      break;
    }
    case HSK_DNS_DNSKEY: {
      hsk_dns_dnskey_rr_t *r = (hsk_dns_dnskey_rr_t *)rr;

      if (!read_u16be(data, data_len, &r->flags))
        return false;

      if (!read_u8(data, data_len, &r->protocol))
        return false;

      if (!read_u8(data, data_len, &r->algorithm))
        return false;

      r->public_key_len = *data_len;

      if (!alloc_bytes(data, data_len, &r->public_key, *data_len))
        return false;

      break;
    }
    case HSK_DNS_RRSIG: {
      hsk_dns_rrsig_rr_t *r = (hsk_dns_rrsig_rr_t *)rr;

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
      hsk_dns_uri_rr_t *r = (hsk_dns_uri_rr_t *)rr;

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
      hsk_dns_rp_rr_t *r = (hsk_dns_rp_rr_t *)rr;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->mbox))
        return false;

      if (!hsk_dns_name_read(data, data_len, pd, pd_len, r->txt))
        return false;

      break;
    }
    default: {
      hsk_dns_unknown_rr_t *r = (hsk_dns_unknown_rr_t *)rr;

      r->rd_len = *data_len;

      if (!alloc_bytes(data, data_len, &r->rd, *data_len))
        return false;

      break;
    }
  }

  return true;
}

void
hsk_dns_txts_init(hsk_dns_txts_t *txts) {
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

        glue = ((hsk_dns_cname_rr_t *)rr)->target;
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
  int32_t max = 255;
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
        if (off + c > data_len)
          return -1; // EOF

        int32_t j;
        for (j = off; j < off + c; j++) {
          uint8_t b = data[j];

          if (b == 0)
            return -1;

          if (b < 0x20 || b > 0x7e)
            return -1;

          if (noff + 1 > max)
            return -1;

          if (name)
            name[noff] = b;

          noff += 1;
        }

        if (noff + 1 > max)
          return -1;

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

int32_t
hsk_dns_name_write(char *name, uint8_t **data) {
  int32_t off = 0;
  int32_t begin = 0;
  int32_t i;
  char *s;

  for (s = name, i = 0; *s; s++, i++) {
    if (i >= 255)
      return off; // fail

    if (name[i] == '.') {
      if (i > 0 && name[i - 1] == '.')
        return off; // fail

      if (i - begin >= (1 << 6))
        return off; // fail

      if (off + 1 > 256)
        return off; // fail

      if (data)
        (*data)[off] = (i - begin) & 0xff;

      off += 1;

      int32_t j;
      for (j = begin; j < i; j++) {
        if (off + 1 > 256)
          return off; // fail

        if (data)
          (*data)[off] = name[j];

        off += 1;
      }

      begin = i + 1;
    }
  }

  if (i == 0 || name[i - 1] != '.')
    return off; // fail

  if (i == 1 && name[0] == '.') {
    if (data)
      *data += off;
    return off;
  }

  if (off + 1 > 256)
    return off; // fail

  if (data)
    (*data)[off] = 0;

  off += 1;

  if (data)
    *data += off;

  return off;
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

void
hsk_dns_label_split(char *fqdn, uint8_t *labels, int32_t *count) {
  size_t len = strlen(fqdn);
  bool dot = false;
  int32_t i;
  int32_t j = 0;

  for (i = 0; i < len; i++) {
    if (j == 255)
      break;

    if (dot) {
      if (labels)
        labels[j++] = i;
      dot = false;
      continue;
    }

    if (fqdn[i] == '.') {
      dot = true;
      continue;
    }
  }

  if (count)
    *count = j;
}

int32_t
hsk_dns_label_count(char *fqdn) {
  int32_t count;
  hsk_dns_label_split(fqdn, NULL, &count);
  return count;
}

void
hsk_dns_label_from2(
  char *fqdn,
  uint8_t *labels,
  int32_t count,
  int32_t index,
  char *ret
) {
  if (index < 0)
    index += count;

  if (index >= count) {
    ret[0] = '\0';
    return;
  }

  size_t start = (size_t)labels[index];
  size_t end = strlen(fqdn);
  size_t len = end - start;

  memcpy(ret, fqdn + start, len);

  ret[len] = '\0';
}

void
hsk_dns_label_from(char *fqdn, int32_t index, char *ret) {
  uint8_t labels[255];
  int32_t count;
  hsk_dns_label_split(fqdn, labels, &count);
  hsk_dns_label_from2(fqdn, labels, count, index, ret);
}

void
hsk_dns_label_get2(
  char *fqdn,
  uint8_t *labels,
  int32_t count,
  int32_t index,
  char *ret
) {
  if (index < 0)
    index += count;

  if (index >= count) {
    ret[0] = '\0';
    return;
  }

  size_t start = (size_t)labels[index];
  size_t end;

  if (index + 1 >= count)
    end = strlen(fqdn);
  else
    end = ((size_t)labels[index + 1]) - 1;

  size_t len = end - start;

  memcpy(ret, fqdn + start, len);

  ret[len] = '\0';
}

void
hsk_dns_label_get(char *fqdn, int32_t index, char *ret) {
  uint8_t labels[255];
  int32_t count;
  hsk_dns_label_split(fqdn, labels, &count);
  hsk_dns_label_get2(fqdn, labels, count, index, ret);
}

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
