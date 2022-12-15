#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>

#include "bio.h"
#include "dns.h"
#include "ecc.h"
#include "map.h"
#include "sha256.h"
#include "utils.h"

typedef struct hsk_dns_raw_rr_s {
  uint8_t *data;
  size_t size;
} hsk_dns_raw_rr_t;

static int
raw_rr_cmp(const void *a, const void *b);

static bool
raw_rr_equal(const hsk_dns_raw_rr_t *a, const hsk_dns_raw_rr_t *b);

/*
 * Message
 */

void
hsk_dns_msg_init(hsk_dns_msg_t *msg) {
  assert(msg);
  msg->id = 0;
  msg->opcode = HSK_DNS_QUERY;
  msg->code = HSK_DNS_NOERROR;
  msg->flags = 0;
  hsk_dns_rrs_init(&msg->qd);
  hsk_dns_rrs_init(&msg->an);
  hsk_dns_rrs_init(&msg->ns);
  hsk_dns_rrs_init(&msg->ar);
  msg->edns.enabled = false;
  msg->edns.version = 0;
  msg->edns.flags = 0;
  msg->edns.size = HSK_DNS_MAX_UDP;
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
hsk_dns_msg_decode(const uint8_t *data, size_t data_len, hsk_dns_msg_t **msg) {
  hsk_dns_msg_t *m = hsk_dns_msg_alloc();

  if (!m)
    return false;

  if (!hsk_dns_msg_read((uint8_t **)&data, &data_len, m)) {
    hsk_dns_msg_free(m);
    return false;
  }

  *msg = m;

  return true;
}

int
hsk_dns_msg_write(const hsk_dns_msg_t *msg, uint8_t **data) {
  int size = 0;
  uint16_t flags = msg->flags;

  hsk_dns_cmp_t cmp_;
  hsk_dns_cmp_t *cmp = NULL;

  if (data) {
    cmp = &cmp_;
    hsk_map_init_str_map(&cmp->map, NULL);
    cmp->msg = *data;
  }

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

  int i;

  for (i = 0; i < msg->qd.size; i++)
    size += hsk_dns_qs_write(msg->qd.items[i], data, cmp);

  for (i = 0; i < msg->an.size; i++)
    size += hsk_dns_rr_write(msg->an.items[i], data, cmp);

  for (i = 0; i < msg->ns.size; i++)
    size += hsk_dns_rr_write(msg->ns.items[i], data, cmp);

  for (i = 0; i < msg->ar.size; i++)
    size += hsk_dns_rr_write(msg->ar.items[i], data, cmp);

  bool enabled = msg->edns.enabled;
  uint16_t ecode = msg->edns.code;

  if (msg->code > 0x0f) {
    enabled = true;
    ecode = msg->code >> 4;
  }

  if (enabled) {
    hsk_dns_rr_t rr = { .type = HSK_DNS_OPT };
    hsk_dns_opt_rd_t rd;
    strcpy(rr.name, ".");
    rr.ttl = 0;
    rr.ttl |= ((uint32_t)ecode) << 24;
    rr.ttl |= ((uint32_t)msg->edns.version) << 16;
    rr.ttl |= (uint32_t)msg->edns.flags;
    rr.class = msg->edns.size;
    rr.rd = (void *)&rd;
    rd.rd_len = msg->edns.rd_len;
    rd.rd = msg->edns.rd;
    size += hsk_dns_rr_write(&rr, data, cmp);
  }

  if (cmp)
    hsk_map_uninit(&cmp->map);

  return size;
}

int
hsk_dns_msg_size(const hsk_dns_msg_t *msg) {
  return hsk_dns_msg_write(msg, NULL);
}

bool
hsk_dns_msg_encode(const hsk_dns_msg_t *msg, uint8_t **data, size_t *data_len) {
  int size = hsk_dns_msg_size(msg);
  uint8_t *buf = malloc(size);

  if (!buf)
    return false;

  uint8_t *b = buf;

  // Will yield something less
  // due to label compression.
  size = hsk_dns_msg_write(msg, &b);

  *data = buf;
  *data_len = size;

  return true;
}

bool
hsk_dns_msg_truncate(uint8_t *msg, size_t msg_len, size_t max, size_t *len) {
  if (msg_len < 12)
    return false;

  if (max < 12)
    return false;

  if (msg_len <= max) {
    *len = msg_len;
    return true;
  }

  uint8_t *data = msg;
  size_t data_len = msg_len;

  uint16_t flags = 0;
  uint16_t qdcount = 0;
  uint16_t ancount = 0;
  uint16_t nscount = 0;
  uint16_t arcount = 0;

  hsk_dns_dmp_t dmp;
  dmp.msg = msg;
  dmp.msg_len = msg_len;

  data += 2;
  data_len -= 2;

  if (!read_u16be(&data, &data_len, &flags))
    return false;

  if (!read_u16be(&data, &data_len, &qdcount))
    return false;

  if (!read_u16be(&data, &data_len, &ancount))
    return false;

  if (!read_u16be(&data, &data_len, &nscount))
    return false;

  if (!read_u16be(&data, &data_len, &arcount))
    return false;

  uint8_t *end = msg + max;
  uint8_t *last = data;
  uint16_t rdlen;

  uint16_t counts[4] = {
    qdcount,
    ancount,
    nscount,
    arcount
  };

  int s;
  for (s = 0; s < 4; s++) {
    uint16_t count = counts[s];
    int i = 0;
    int j = 0;

    while (data <= end) {
      last = data;
      j = i;

      if (i == count)
        break;

      i += 1;

      if (!hsk_dns_name_read(&data, &data_len, &dmp, NULL))
        return false;

      // Question.
      if (s == 0) {
        // QS header.
        if (data_len < 4)
          return false;

        // Type and class.
        data += 4;
        data_len -= 4;

        continue;
      }

      // RR header.
      if (data_len < 8)
        return false;

      // Type, class, TTL.
      data += 8;
      data_len -= 8;

      // RD len.
      if (!read_u16be(&data, &data_len, &rdlen))
        return false;

      if (data_len < rdlen)
        return false;

      data += rdlen;
      data_len -= rdlen;
    }

    counts[s] = j;
  }

  flags |= HSK_DNS_TC;

  // We would normally set the truncate bit,
  // but we don't support TCP yet.
  // msg[2] = (flags >> 8) & 0xff;
  // msg[3] = flags & 0xff;

  msg[4] = (counts[0] >> 8) & 0xff;
  msg[5] = counts[0] & 0xff;
  msg[6] = (counts[1] >> 8) & 0xff;
  msg[7] = counts[1] & 0xff;
  msg[8] = (counts[2] >> 8) & 0xff;
  msg[9] = counts[2] & 0xff;
  msg[10] = (counts[3] >> 8) & 0xff;
  msg[11] = counts[3] & 0xff;

  *len = last - msg;

  return true;
}

bool
hsk_dns_msg_read(uint8_t **data, size_t *data_len, hsk_dns_msg_t *msg) {
  uint16_t id = 0;
  uint16_t flags = 0;
  uint16_t qdcount = 0;
  uint16_t ancount = 0;
  uint16_t nscount = 0;
  uint16_t arcount = 0;

  hsk_dns_dmp_t dmp;
  dmp.msg = *data;
  dmp.msg_len = *data_len;

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

    if (!hsk_dns_qs_read(data, data_len, &dmp, qs))
      goto fail;

    hsk_dns_rrs_push(&msg->qd, qs);
  }

  for (i = 0; i < ancount; i++) {
    if (*data_len == 0)
      break;

    hsk_dns_rr_t *rr = hsk_dns_rr_alloc();

    if (!rr)
      goto fail;

    if (!hsk_dns_rr_read(data, data_len, &dmp, rr))
      goto fail;

    hsk_dns_rrs_push(&msg->an, rr);
  }

  for (i = 0; i < nscount; i++) {
    if (*data_len == 0)
      break;

    hsk_dns_rr_t *rr = hsk_dns_rr_alloc();

    if (!rr)
      goto fail;

    if (!hsk_dns_rr_read(data, data_len, &dmp, rr))
      goto fail;

    hsk_dns_rrs_push(&msg->ns, rr);
  }

  for (i = 0; i < arcount; i++) {
    if (*data_len == 0)
      break;

    hsk_dns_rr_t *rr = hsk_dns_rr_alloc();

    if (!rr)
      goto fail;

    if (!hsk_dns_rr_read(data, data_len, &dmp, rr))
      goto fail;

    if (rr->type == HSK_DNS_OPT) {
      hsk_dns_opt_rd_t *opt = (hsk_dns_opt_rd_t *)rr->rd;

      if (msg->edns.rd)
        free(msg->edns.rd);

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

  int i;
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

  int i;
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

  int i;
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
hsk_dns_rrs_get(hsk_dns_rrs_t *rrs, int index) {
  assert(rrs);

  if (index < 0)
    index += rrs->size;

  if (index >= rrs->size)
    return NULL;

  return rrs->items[index];
}

size_t
hsk_dns_rrs_set(hsk_dns_rrs_t *rrs, int index, hsk_dns_rr_t *rr) {
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
  strcpy(qs->name, ".");
  qs->type = HSK_DNS_UNKNOWN;
  qs->class = HSK_DNS_IN;
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
hsk_dns_qs_set(hsk_dns_qs_t *qs, const char *name, uint16_t type) {
  assert(qs && name);
  assert(strlen(name) <= 255);
  strcpy(qs->name, name);
  qs->type = type;
}

int
hsk_dns_qs_write(const hsk_dns_qs_t *qs, uint8_t **data, hsk_dns_cmp_t *cmp) {
  int size = 0;
  size += hsk_dns_name_write(qs->name, data, cmp);
  size += write_u16be(data, qs->type);
  size += write_u16be(data, qs->class);
  return size;
}

bool
hsk_dns_qs_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  hsk_dns_qs_t *qs
) {
  if (!hsk_dns_name_read(data, data_len, dmp, qs->name))
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
  strcpy(rr->name, ".");
  rr->type = HSK_DNS_UNKNOWN;
  rr->class = HSK_DNS_IN;
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

bool
hsk_dns_rr_set_name(hsk_dns_rr_t *rr, const char *name) {
  assert(rr);

  if (!hsk_dns_name_verify(name))
    return false;

  if (hsk_dns_name_dirty(name))
    return false;

  if (hsk_dns_name_is_fqdn(name))
    strcpy(rr->name, name);
  else
    sprintf(rr->name, "%s.", name);

  return true;
}

int
hsk_dns_rr_write(const hsk_dns_rr_t *rr, uint8_t **data, hsk_dns_cmp_t *cmp) {
  int size = 0;

  size += hsk_dns_name_write(rr->name, data, cmp);
  size += write_u16be(data, rr->type);
  size += write_u16be(data, rr->class);
  size += write_u32be(data, rr->ttl);

  if (!rr->rd) {
    size += write_u16be(data, 0);
    return size;
  }

  // Save RD len pos for later.
  uint8_t *pos = NULL;

  if (data) {
    pos = *data;
    *data += 2;
  }

  size += 2;

  // Write RD.
  int rdlen = hsk_dns_rd_write(rr->rd, rr->type, data, cmp);
  size += rdlen;

  // Write RD len.
  if (pos)
    write_u16be(&pos, rdlen);

  return size;
}

int
hsk_dns_rr_size(const hsk_dns_rr_t *rr) {
  return hsk_dns_rr_write(rr, NULL, NULL);
}

bool
hsk_dns_rr_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  hsk_dns_rr_t *rr
) {
  if (!hsk_dns_name_read(data, data_len, dmp, rr->name))
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

  if (!hsk_dns_rd_read(&rdata, &rdlen, dmp, rd, rr->type)) {
    free(rd);
    return false;
  }

  rr->rd = rd;

  *data += len;
  *data_len -= len;

  return true;
}

bool
hsk_dns_rr_encode(const hsk_dns_rr_t *rr, uint8_t **data, size_t *data_len) {
  if (!rr || !data)
    return false;

  size_t size = hsk_dns_rr_size(rr);
  uint8_t *raw = malloc(size);

  if (!raw)
    return false;

  uint8_t *d = raw;
  hsk_dns_rr_write(rr, &d, NULL);

  *data = raw;
  *data_len = size;

  return true;
}

bool
hsk_dns_rr_decode(const uint8_t *data, size_t data_len, hsk_dns_rr_t **out) {
  if (!data || !out)
    return false;

  hsk_dns_rr_t *rr = hsk_dns_rr_alloc();

  if (!rr)
    return false;

  uint8_t *raw = (uint8_t *)data;
  size_t size = data_len;

  if (!hsk_dns_rr_read(&raw, &size, NULL, rr)) {
    hsk_dns_rr_free(rr);
    return false;
  }

  *out = rr;

  return true;
}

hsk_dns_rr_t *
hsk_dns_rr_clone(const hsk_dns_rr_t *rr) {
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
      strcpy(r->ns, ".");
      strcpy(r->mbox, ".");
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
    case HSK_DNS_LOC: {
      hsk_dns_loc_rd_t *r = (hsk_dns_loc_rd_t *)rd;
      r->version = 0;
      r->size = 0;
      r->horiz_pre = 0;
      r->vert_pre = 0;
      r->latitude = 0;
      r->longitude = 0;
      r->altitude = 0;
      break;
    }
    case HSK_DNS_CNAME: {
      hsk_dns_cname_rd_t *r = (hsk_dns_cname_rd_t *)rd;
      memset(r->target, 0, sizeof(r->target));
      strcpy(r->target, ".");
      break;
    }
    case HSK_DNS_DNAME: {
      hsk_dns_dname_rd_t *r = (hsk_dns_dname_rd_t *)rd;
      memset(r->target, 0, sizeof(r->target));
      strcpy(r->target, ".");
      break;
    }
    case HSK_DNS_NS: {
      hsk_dns_ns_rd_t *r = (hsk_dns_ns_rd_t *)rd;
      memset(r->ns, 0, sizeof(r->ns));
      strcpy(r->ns, ".");
      break;
    }
    case HSK_DNS_MX: {
      hsk_dns_mx_rd_t *r = (hsk_dns_mx_rd_t *)rd;
      r->preference = 0;
      memset(r->mx, 0, sizeof(r->mx));
      strcpy(r->mx, ".");
      break;
    }
    case HSK_DNS_PTR: {
      hsk_dns_ptr_rd_t *r = (hsk_dns_ptr_rd_t *)rd;
      memset(r->ptr, 0, sizeof(r->ptr));
      strcpy(r->ptr, ".");
      break;
    }
    case HSK_DNS_SRV: {
      hsk_dns_srv_rd_t *r = (hsk_dns_srv_rd_t *)rd;
      r->priority = 0;
      r->weight = 0;
      r->port = 0;
      memset(r->target, 0, sizeof(r->target));
      strcpy(r->target, ".");
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
    case HSK_DNS_SMIMEA:
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
      strcpy(r->mbox, ".");
      strcpy(r->txt, ".");
      break;
    }
    case HSK_DNS_NSEC: {
      hsk_dns_nsec_rd_t *r = (hsk_dns_nsec_rd_t *)rd;
      memset(r->next_domain, 0, sizeof(r->next_domain));
      strcpy(r->next_domain, ".");
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
      break;
    }
    case HSK_DNS_A: {
      break;
    }
    case HSK_DNS_AAAA: {
      break;
    }
    case HSK_DNS_LOC: {
      break;
    }
    case HSK_DNS_CNAME: {
      break;
    }
    case HSK_DNS_DNAME: {
      break;
    }
    case HSK_DNS_NS: {
      break;
    }
    case HSK_DNS_MX: {
      break;
    }
    case HSK_DNS_PTR: {
      break;
    }
    case HSK_DNS_SRV: {
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
    case HSK_DNS_SMIMEA:
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
      break;
    }
    case HSK_DNS_RP: {
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
    case HSK_DNS_LOC: {
      rd = malloc(sizeof(hsk_dns_loc_rd_t));
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
    case HSK_DNS_SMIMEA:
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

int
hsk_dns_rd_write(
  const void *rd,
  uint16_t type,
  uint8_t **data,
  hsk_dns_cmp_t *cmp
) {
  int size = 0;

  switch (type) {
    case HSK_DNS_SOA: {
      hsk_dns_soa_rd_t *r = (hsk_dns_soa_rd_t *)rd;

      size += hsk_dns_name_write(r->ns, data, cmp);
      size += hsk_dns_name_write(r->mbox, data, cmp);
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
    case HSK_DNS_LOC: {
      hsk_dns_loc_rd_t *r = (hsk_dns_loc_rd_t *)rd;

      size += write_u8(data, r->version);
      size += write_u8(data, r->size);
      size += write_u8(data, r->horiz_pre);
      size += write_u8(data, r->vert_pre);
      size += write_u32be(data, r->latitude);
      size += write_u32be(data, r->longitude);
      size += write_u32be(data, r->altitude);

      break;
    }
    case HSK_DNS_CNAME: {
      hsk_dns_cname_rd_t *r = (hsk_dns_cname_rd_t *)rd;

      size += hsk_dns_name_write(r->target, data, cmp);

      break;
    }
    case HSK_DNS_DNAME: {
      hsk_dns_dname_rd_t *r = (hsk_dns_dname_rd_t *)rd;

      size += hsk_dns_name_write(r->target, data, cmp);

      break;
    }
    case HSK_DNS_NS: {
      hsk_dns_ns_rd_t *r = (hsk_dns_ns_rd_t *)rd;

      size += hsk_dns_name_write(r->ns, data, cmp);

      break;
    }
    case HSK_DNS_MX: {
      hsk_dns_mx_rd_t *r = (hsk_dns_mx_rd_t *)rd;

      size += write_u16be(data, r->preference);
      size += hsk_dns_name_write(r->mx, data, cmp);

      break;
    }
    case HSK_DNS_PTR: {
      hsk_dns_ptr_rd_t *r = (hsk_dns_ptr_rd_t *)rd;

      size += hsk_dns_name_write(r->ptr, data, cmp);

      break;
    }
    case HSK_DNS_SRV: {
      hsk_dns_srv_rd_t *r = (hsk_dns_srv_rd_t *)rd;

      size += write_u16be(data, r->priority);
      size += write_u16be(data, r->weight);
      size += write_u16be(data, r->port);
      size += hsk_dns_name_write(r->target, data, cmp);

      break;
    }
    case HSK_DNS_TXT: {
      hsk_dns_txt_rd_t *r = (hsk_dns_txt_rd_t *)rd;

      int i;
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
    case HSK_DNS_SMIMEA:
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
      size += hsk_dns_name_write(r->signer_name, data, cmp);
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

      size += hsk_dns_name_write(r->mbox, data, cmp);
      size += hsk_dns_name_write(r->txt, data, cmp);

      break;
    }
    case HSK_DNS_NSEC: {
      hsk_dns_nsec_rd_t *r = (hsk_dns_nsec_rd_t *)rd;

      size += hsk_dns_name_write(r->next_domain, data, cmp);
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

int
hsk_dns_rd_size(const void *rd, uint16_t type) {
  return hsk_dns_rd_write(rd, type, NULL, NULL);
}

bool
hsk_dns_rd_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  void *rd,
  uint16_t type
) {
  switch (type) {
    case HSK_DNS_SOA: {
      hsk_dns_soa_rd_t *r = (hsk_dns_soa_rd_t *)rd;

      if (!hsk_dns_name_read(data, data_len, dmp, r->ns))
        return false;

      if (!hsk_dns_name_read(data, data_len, dmp, r->mbox))
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
    case HSK_DNS_LOC: {
      hsk_dns_loc_rd_t *r = (hsk_dns_loc_rd_t *)rd;

      if (!read_u8(data, data_len, &r->version))
        return false;

      if (!read_u8(data, data_len, &r->size))
        return false;

      if (!read_u8(data, data_len, &r->horiz_pre))
        return false;

      if (!read_u8(data, data_len, &r->vert_pre))
        return false;

      if (!read_u32be(data, data_len, &r->latitude))
        return false;

      if (!read_u32be(data, data_len, &r->longitude))
        return false;

      if (!read_u32be(data, data_len, &r->altitude))
        return false;

      break;
    }
    case HSK_DNS_CNAME: {
      hsk_dns_cname_rd_t *r = (hsk_dns_cname_rd_t *)rd;

      if (!hsk_dns_name_read(data, data_len, dmp, r->target))
        return false;

      break;
    }
    case HSK_DNS_DNAME: {
      hsk_dns_dname_rd_t *r = (hsk_dns_dname_rd_t *)rd;

      if (!hsk_dns_name_read(data, data_len, dmp, r->target))
        return false;

      break;
    }
    case HSK_DNS_NS: {
      hsk_dns_ns_rd_t *r = (hsk_dns_ns_rd_t *)rd;

      if (!hsk_dns_name_read(data, data_len, dmp, r->ns))
        return false;

      break;
    }
    case HSK_DNS_MX: {
      hsk_dns_mx_rd_t *r = (hsk_dns_mx_rd_t *)rd;

      if (!read_u16be(data, data_len, &r->preference))
        return false;

      if (!hsk_dns_name_read(data, data_len, dmp, r->mx))
        return false;

      break;
    }
    case HSK_DNS_PTR: {
      hsk_dns_ptr_rd_t *r = (hsk_dns_ptr_rd_t *)rd;

      if (!hsk_dns_name_read(data, data_len, dmp, r->ptr))
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

      if (!hsk_dns_name_read(data, data_len, dmp, r->target))
        return false;

      break;
    }
    case HSK_DNS_TXT: {
      hsk_dns_txt_rd_t *r = (hsk_dns_txt_rd_t *)rd;

      while (*data_len > 0) {
        hsk_dns_txt_t *txt = hsk_dns_txt_alloc();

        if (!txt)
          goto fail_txt;

        if (!read_u8(data, data_len, &txt->data_len)) {
          hsk_dns_txt_free(txt);
          goto fail_txt;
        }

        if (!read_bytes(data, data_len, txt->data, txt->data_len)) {
          hsk_dns_txt_free(txt);
          goto fail_txt;
        }

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
    case HSK_DNS_SMIMEA:
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

      if (!hsk_dns_name_read(data, data_len, dmp, r->signer_name))
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

      if (!hsk_dns_name_read(data, data_len, dmp, r->mbox))
        return false;

      if (!hsk_dns_name_read(data, data_len, dmp, r->txt))
        return false;

      break;
    }
    case HSK_DNS_NSEC: {
      hsk_dns_nsec_rd_t *r = (hsk_dns_nsec_rd_t *)rd;

      if (!hsk_dns_name_read(data, data_len, dmp, r->next_domain))
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
hsk_dns_rd_encode(
  const void *rd,
  uint16_t type,
  uint8_t **data,
  size_t *data_len
 ) {
  if (!rd || !data || !data_len)
    return false;

  size_t size = hsk_dns_rd_size(rd, type);
  uint8_t *raw = malloc(size);

  if (!raw)
    return false;

  uint8_t *d = raw;
  hsk_dns_rd_write(rd, type, &d, NULL);

  *data = raw;
  *data_len = size;

  return true;
}

bool
hsk_dns_rd_decode(
  const uint8_t *data,
  size_t data_len,
  uint16_t type,
  void **out
) {
  if (!data || !out)
    return false;

  void *rd = hsk_dns_rd_alloc(type);

  if (!rd)
    return false;

  uint8_t *raw = (uint8_t *)data;
  size_t size = data_len;

  if (!hsk_dns_rd_read(&raw, &size, NULL, rd, type)) {
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

  int i;
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

  int i;
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

  int i;
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
hsk_dns_txts_get(hsk_dns_txts_t *txts, int index) {
  assert(txts);

  if (index < 0)
    index += txts->size;

  if (index >= txts->size)
    return NULL;

  return txts->items[index];
}

size_t
hsk_dns_txts_set(hsk_dns_txts_t *txts, int index, hsk_dns_txt_t *txt) {
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
 * Names
 */

int
hsk_dns_name_parse(
  uint8_t **data_,
  size_t *data_len_,
  const hsk_dns_dmp_t *dmp,
  char *name
) {
  uint8_t *data = *data_;
  size_t data_len = *data_len_;
  int off = 0;
  int noff = 0;
  int res = 0;
  int max = HSK_DNS_MAX_NAME;
  int ptr = 0;

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

        int j;
        for (j = off; j < off + c; j++) {
          uint8_t b = data[j];

          // Hack because we're
          // using c-strings.
          if (b == 0x00)
            b = 0xff;

          // This allows for double-dots
          // too easily in our design.
          if (b == 0x2e)
            b = 0xfe;

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
        if (!dmp)
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

        off = (((int)(c ^ 0xc0)) << 8) | c1;

        data = dmp->msg;
        data_len = dmp->msg_len;

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
hsk_dns_name_serialize(
  const char *name,
  uint8_t *data,
  int *len,
  hsk_dns_cmp_t *cmp
) {
  int off = 0;
  int pos = -1;
  int ptr = -1;
  int begin = 0;
  size_t data_len = 256;
  int size;
  int i;
  char *s;

  for (s = (char *)name, i = 0; *s; s++, i++) {
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

      if (cmp) {
        char *sub = (char *)&name[begin];
        if (strcmp(sub, ".") != 0) {
          size_t p = (size_t)hsk_map_get(&cmp->map, sub);
          if (p == 0) {
            size_t o = (size_t)(&data[off] - cmp->msg);
            if (o < (2 << 13))
              hsk_map_set(&cmp->map, sub, (void *)o);
          } else {
            if (ptr == -1) {
              ptr = p;
              pos = off;
              i += strlen(s);
              break;
            }
          }
        }
      }

      off += 1;

      if (data) {
        int j;
        for (j = begin; j < i; j++) {
          char ch = name[j];

          // 0xff -> NUL
          if (ch == -1)
            ch = '\0';

          // 0xfe -> .
          if (ch == -2)
            ch = '.';

          data[off++] = ch;
        }
      } else {
        off += size;
      }

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
    return true;
  }

  if (ptr != -1) {
    off = pos;

    if (data) {
      if (off + 2 > data_len)
        return false;
      ptr ^= 0xc000;
      data[off] = (ptr >> 8) & 0xff;
      data[off + 1] = ptr & 0xff;
    }

    off += 2;
    *len = off;

    return true;
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

  return true;
}

int
hsk_dns_name_pack(const char *name, uint8_t *data) {
  int len;
  if (!hsk_dns_name_serialize(name, data, &len, NULL))
    return 0;
  return len;
}

int
hsk_dns_name_write(const char *name, uint8_t **data, hsk_dns_cmp_t *cmp) {
  uint8_t *buf = data ? *data : NULL;
  int len;

  hsk_dns_name_serialize(name, buf, &len, cmp);

  if (data)
    *data += len;

  return len;
}

bool
hsk_dns_name_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  char *name
) {
  return hsk_dns_name_parse(data, data_len, dmp, name) != -1;
}

int
hsk_dns_name_read_size(
  const uint8_t *data,
  size_t data_len,
  const hsk_dns_dmp_t *dmp
) {
  return hsk_dns_name_parse((uint8_t **)&data, &data_len, dmp, NULL);
}

bool
hsk_dns_name_alloc(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  char **name
) {
  int size = hsk_dns_name_read_size(*data, *data_len, dmp);

  if (size == -1)
    return false;

  char *n = malloc(size + 1);

  if (!n)
    return false;

  assert(hsk_dns_name_read(data, data_len, dmp, n));

  *name = n;

  return true;
}

bool
hsk_dns_name_dirty(const char *name) {
  char *s = (char *)name;

  while (*s) {
    uint8_t c = (uint8_t)*s;

    switch (c) {
      case 0x28 /*(*/:
      case 0x29 /*)*/:
      case 0x3b /*;*/:
      case 0x20 /* */:
      case 0x40 /*@*/:
      case 0x22 /*"*/:
      case 0x5c /*\\*/:
        return true;
    }

    if (c < 0x20 || c > 0x7e)
      return true;

    s += 1;
  }

  return false;
}

void
hsk_dns_name_sanitize(const char *name, char *out) {
  char *s = (char *)name;
  int off = 0;

  while (*s && off < HSK_DNS_MAX_SANITIZED) {
    uint8_t c = (uint8_t)*s;

    switch (c) {
      case 0xfe: {
        c = 0x2e;
        ; // fall through
      }
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
hsk_dns_name_verify(const char *name) {
  if (name == NULL)
    return false;

  char *n = (char *)name;
  size_t len = strlen(n);
  char buf[HSK_DNS_MAX_NAME + 1];

  if (len == 0 || n[len - 1] != '.') {
    if (len + 1 > HSK_DNS_MAX_NAME)
      return false;

    memcpy(&buf[0], n, len);
    n = &buf[0];
    n[len + 0] = '.';
    n[len + 1] = '\0';

    len += 1;
  }

  if (len > HSK_DNS_MAX_NAME)
    return false;

  return hsk_dns_name_pack(n, NULL) != 0;
}

bool
hsk_dns_name_is_fqdn(const char *name) {
  if (name == NULL)
    return false;

  size_t len = strlen(name);

  if (len == 0 || name[len - 1] != '.')
    return false;

  return true;
}

int
hsk_dns_name_cmp(const char *a, const char *b) {
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

  int i;
  for (i = 0; i < len; i++) {
    uint8_t x = (uint8_t)a[i];
    uint8_t y = (uint8_t)b[i];

    if (x >= 0x41 && x <= 0x5a)
      x |= 0x20;

    if (y >= 0x41 && y <= 0x5a)
      y |= 0x20;

    if (x < y)
      return -1;

    if (x > y)
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

int
hsk_dns_label_split(const char *name, uint8_t *labels, size_t size) {
  char *s = (char *)name;
  bool dot = true;
  int count = 0;
  int i;

  if (!labels)
    size = HSK_DNS_MAX_LABELS;

  for (i = 0; *s && count < size; s++, i++) {
    if (*s == '.') {
      dot = true;
      continue;
    }

    if (dot) {
      if (labels)
        labels[count] = i;
      count += 1;
      dot = false;
      continue;
    }
  }

  return count;
}

int
hsk_dns_label_count(const char *name) {
  return hsk_dns_label_split(name, NULL, 0);
}

int
hsk_dns_label_from2(
  const char *name,
  uint8_t *labels,
  int count,
  int index,
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

int
hsk_dns_label_from(const char *name, int index, char *ret) {
  int count = hsk_dns_label_count(name);

  if (count == 0) {
    ret[0] = '\0';
    return 0;
  }

  uint8_t labels[count];

  assert(hsk_dns_label_split(name, labels, count) == count);

  return hsk_dns_label_from2(name, labels, count, index, ret);
}

int
hsk_dns_label_get2(
  const char *name,
  uint8_t *labels,
  int count,
  int index,
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

int
hsk_dns_label_get(const char *name, int index, char *ret) {
  int count = hsk_dns_label_count(name);

  if (count == 0) {
    ret[0] = '\0';
    return 0;
  }

  uint8_t labels[count];

  assert(hsk_dns_label_split(name, labels, count) == count);

  return hsk_dns_label_get2(name, labels, count, index, ret);
}

bool
hsk_dns_label_decode_srv(const char *name, char *protocol, char *service) {
  int count = hsk_dns_label_count(name);

  if (count < 3)
    return false;

  uint8_t labels[count];

  assert(hsk_dns_label_split(name, labels, count) == count);

  char label[HSK_DNS_MAX_LABEL + 1];
  int len;

  len = hsk_dns_label_get2(name, labels, count, 1, label);

  if (len < 2)
    return false;

  if (label[0] != '_')
    return false;

  if (protocol) {
    strcpy(protocol, &label[1]);
    hsk_to_lower(protocol);
  }

  len = hsk_dns_label_get2(name, labels, count, 0, label);

  if (len < 2)
    return false;

  if (label[0] != '_')
    return false;

  if (service) {
    strcpy(service, &label[1]);
    hsk_to_lower(service);
  }

  return true;
}

bool
hsk_dns_label_is_srv(const char *name) {
  return hsk_dns_label_decode_srv(name, NULL, NULL);
}

bool
hsk_dns_label_decode_tlsa(const char *name, char *protocol, uint16_t *port) {
  int count = hsk_dns_label_count(name);

  if (count < 3)
    return false;

  uint8_t labels[count];

  assert(hsk_dns_label_split(name, labels, count) == count);

  char label[HSK_DNS_MAX_LABEL + 1];
  int len;

  len = hsk_dns_label_get2(name, labels, count, 1, label);

  if (len < 2)
    return false;

  if (label[0] != '_')
    return false;

  if (protocol) {
    strcpy(protocol, &label[1]);
    hsk_to_lower(protocol);
  }

  len = hsk_dns_label_get2(name, labels, count, 0, label);

  if (len < 2 || len > 6)
    return false;

  if (label[0] != '_')
    return false;

  uint32_t word = 0;
  char *s = &label[1];

  while (*s) {
    int ch = ((int)*s) - 0x30;

    if (ch < 0 || ch > 9)
      return false;

    word *= 10;
    word += ch;

    if (word > 0xffff)
      return false;

    s += 1;
  }

  if (port)
    *port = (uint16_t)word;

  return true;
}

bool
hsk_dns_label_is_tlsa(const char *name) {
  return hsk_dns_label_decode_tlsa(name, NULL, NULL);
}

static bool
hsk_dns_label_decode_dane(const char *tag, const char *name, uint8_t *hash) {
  int count = hsk_dns_label_count(name);

  if (count < 3)
    return false;

  uint8_t labels[count];

  assert(hsk_dns_label_split(name, labels, count) == count);

  char label[HSK_DNS_MAX_LABEL + 1];
  int len;

  len = hsk_dns_label_get2(name, labels, count, 1, label);

  if (len < 2)
    return false;

  if (strcasecmp(label, tag) != 0)
    return false;

  len = hsk_dns_label_get2(name, labels, count, 0, label);

  if (len != 56)
    return false;

  if (!hsk_hex_decode(&label[0], hash))
    return false;

  return true;
}

static bool
hsk_dns_label_is_dane(const char *tag, const char *name) {
  return hsk_dns_label_decode_dane(tag, name, NULL);
}

bool
hsk_dns_label_decode_smimea(const char *name, uint8_t *hash) {
  return hsk_dns_label_decode_dane("_smimecert", name, hash);
}

bool
hsk_dns_label_is_smimea(const char *name) {
  return hsk_dns_label_is_dane("_smimecert", name);
}

bool
hsk_dns_label_decode_openpgpkey(const char *name, uint8_t *hash) {
  return hsk_dns_label_decode_dane("_openpgpkey", name, hash);
}

bool
hsk_dns_label_is_openpgpkey(const char *name) {
  return hsk_dns_label_is_dane("_openpgpkey", name);
}

/*
 * DNSSEC
 */

long
hsk_dns_dnskey_keytag(const hsk_dns_dnskey_rd_t *rd) {
  uint8_t *data;
  size_t size;

  if (!hsk_dns_rd_encode(rd, HSK_DNS_DNSKEY, &data, &size))
    return -1;

  uint32_t tag = 0;
  size_t i;

  for (i = 0; i < size; i++) {
    uint32_t ch = (uint32_t)data[i];

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

  hsk_to_lower(rrsig->signer_name);
  rrsig->signature = NULL;
  rrsig->signature_len = 0;

  bool ret = hsk_dns_rd_encode(rrsig, HSK_DNS_RRSIG, data, data_len);

  strcpy(rrsig->signer_name, signer_name);
  rrsig->signature = signature;
  rrsig->signature_len = signature_len;

  return ret;
}

hsk_dns_rr_t *
hsk_dns_dnskey_create(const char *zone, const uint8_t *priv, bool ksk) {
  hsk_dns_rr_t *key = hsk_dns_rr_create(HSK_DNS_DNSKEY);

  if (!key)
    return NULL;

  hsk_dns_dnskey_rd_t *dnskey = key->rd;

  uint8_t *pubkey = malloc(64);

  if (!pubkey) {
    hsk_dns_rr_free(key);
    return NULL;
  }

  if (!hsk_ecc_make_pubkey(priv, pubkey)) {
    free(pubkey);
    hsk_dns_rr_free(key);
    return NULL;
  }

  strcpy(key->name, zone);
  hsk_to_lower(key->name);
  key->type = HSK_DNS_DNSKEY;
  key->class = HSK_DNS_IN;
  key->ttl = 10800;

  dnskey->flags = (1 << 8) | (ksk ? 1 : 0);
  dnskey->protocol = 3;
  dnskey->algorithm = 13; // ECDSAP256SHA256
  dnskey->pubkey_len = 64;
  dnskey->pubkey = pubkey;

  return key;
}

hsk_dns_rr_t *
hsk_dns_ds_create(const hsk_dns_rr_t *key) {
  if (!key || key->type != HSK_DNS_DNSKEY)
    return NULL;

  hsk_dns_dnskey_rd_t *dnskey = (hsk_dns_dnskey_rd_t *)key->rd;

  hsk_dns_rr_t *ds = hsk_dns_rr_create(HSK_DNS_DS);

  if (!ds)
    return NULL;

  hsk_dns_ds_rd_t *dsrd = ds->rd;

  long key_tag = hsk_dns_dnskey_keytag(dnskey);

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
  hsk_to_lower(ds->name);
  ds->type = HSK_DNS_DS;
  ds->class = key->class;
  ds->ttl = key->ttl;

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

  hsk_sha256_ctx ctx;
  hsk_sha256_init(&ctx);
  hsk_sha256_update(&ctx, owner, owner_len);
  hsk_sha256_update(&ctx, data, size);
  hsk_sha256_final(&ctx, digest);

  free(data);

  return ds;
}

bool
hsk_dns_sign_type(
  hsk_dns_rrs_t *rrs,
  uint16_t type,
  const hsk_dns_rr_t *key,
  const uint8_t *priv
) {
  if (!rrs || rrs->size >= 255 || !key || !priv)
    return false;

  hsk_dns_rrs_t *rrset = hsk_dns_rrs_alloc();

  if (!rrset)
    return false;

  int i;
  for (i = 0; i < rrs->size; i++) {
    hsk_dns_rr_t *rr = rrs->items[i];
    if (rr->type == type)
      assert(hsk_dns_rrs_push(rrset, rr));
  }

  hsk_dns_rr_t *sig = hsk_dns_sign_rrset(rrset, key, priv);

  free(rrset);

  if (!sig)
    return false;

  assert(hsk_dns_rrs_push(rrs, sig));

  return true;
}

hsk_dns_rr_t *
hsk_dns_sign_rrset(
  hsk_dns_rrs_t *rrset,
  const hsk_dns_rr_t *key,
  const uint8_t *priv
) {
  if (!rrset || !key || !priv)
    return NULL;

  if (rrset->size == 0)
    return NULL;

  if (key->type != HSK_DNS_DNSKEY)
    return NULL;

  hsk_dns_dnskey_rd_t *dnskey = (hsk_dns_dnskey_rd_t *)key->rd;

  hsk_dns_rr_t *sig = hsk_dns_rr_create(HSK_DNS_RRSIG);

  if (!sig)
    return NULL;

  hsk_dns_rrsig_rd_t *rrsig = sig->rd;

  long key_tag = hsk_dns_dnskey_keytag(dnskey);

  if (key_tag == -1) {
    hsk_dns_rr_free(sig);
    return NULL;
  }

  strcpy(sig->name, rrset->items[0]->name);
  hsk_to_lower(sig->name);
  sig->type = HSK_DNS_RRSIG;
  sig->class = key->class;
  sig->ttl = key->ttl;

  rrsig->key_tag = key_tag;
  strcpy(rrsig->signer_name, key->name);
  hsk_to_lower(rrsig->signer_name);
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
hsk_dns_sign_rrsig(
  hsk_dns_rrs_t *rrset,
  hsk_dns_rr_t *sig,
  const uint8_t *priv
) {
  if (!rrset || rrset->size == 0)
    return false;

  if (!sig || sig->type != HSK_DNS_RRSIG)
    return false;

  if (!priv)
    return false;

  hsk_dns_rrsig_rd_t *rrsig = (hsk_dns_rrsig_rd_t *)sig->rd;

  rrsig->orig_ttl = rrset->items[0]->ttl;
  rrsig->type_covered = rrset->items[0]->type;
  rrsig->labels = hsk_dns_label_count(rrset->items[0]->name);
  rrsig->signature_len = 0;
  rrsig->signature = NULL;

  uint8_t hash[32];

  // Hash with sha256.
  if (!hsk_dns_sighash(rrset, sig, hash))
    return false;

  uint8_t *sigbuf = malloc(64);

  if (!sigbuf)
    return false;

  // Sign with secp256r1.
  if (!hsk_ecc_sign(priv, hash, sigbuf)) {
    free(sigbuf);
    return false;
  }

  rrsig->signature_len = 64;
  rrsig->signature = sigbuf;

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

  int i, j;
  uint8_t *data;
  size_t size;
  bool ret = true;

  for (i = 0; i < rrset->size; i++) {
    hsk_dns_rr_t *item = rrset->items[i];
    hsk_dns_rr_t *rr = hsk_dns_rr_clone(item);

    if (!rr)
      goto fail;

    hsk_to_lower(rr->name);

    rr->ttl = rrsig->orig_ttl;

    switch (rr->type) {
      case HSK_DNS_NS:
        hsk_to_lower(((hsk_dns_ns_rd_t *)rr->rd)->ns);
        break;
      case HSK_DNS_CNAME:
        hsk_to_lower(((hsk_dns_cname_rd_t *)rr->rd)->target);
        break;
      case HSK_DNS_SOA:
        hsk_to_lower(((hsk_dns_soa_rd_t *)rr->rd)->ns);
        hsk_to_lower(((hsk_dns_soa_rd_t *)rr->rd)->mbox);
        break;
      case HSK_DNS_PTR:
        hsk_to_lower(((hsk_dns_ptr_rd_t *)rr->rd)->ptr);
        break;
      case HSK_DNS_MX:
        hsk_to_lower(((hsk_dns_mx_rd_t *)rr->rd)->mx);
        break;
      case HSK_DNS_SIG:
      case HSK_DNS_RRSIG:
        hsk_to_lower(((hsk_dns_rrsig_rd_t *)rr->rd)->signer_name);
        break;
      case HSK_DNS_SRV:
        hsk_to_lower(((hsk_dns_srv_rd_t *)rr->rd)->target);
        break;
      case HSK_DNS_DNAME:
        hsk_to_lower(((hsk_dns_dname_rd_t *)rr->rd)->target);
        break;
    }

    if (!hsk_dns_rr_encode(rr, &data, &size)) {
      hsk_dns_rr_free(rr);
      goto fail;
    }

    hsk_dns_rr_free(rr);

    hsk_dns_raw_rr_t *raw = &records[i];

    raw->size = size;
    raw->data = data;
  }

  qsort((void *)records, rrset->size, sizeof(hsk_dns_raw_rr_t), raw_rr_cmp);

  if (!hsk_dns_rrsig_tbs(rrsig, &data, &size))
    goto fail;

  hsk_sha256_ctx ctx;
  hsk_sha256_init(&ctx);
  hsk_sha256_update(&ctx, data, size);

  free(data);

  hsk_dns_raw_rr_t *last = NULL;

  for (j = 0; j < rrset->size; j++) {
    hsk_dns_raw_rr_t *raw = &records[j];

    if (last && raw_rr_equal(raw, last))
      continue;

    hsk_sha256_update(&ctx, raw->data, raw->size);

    last = raw;
  }

  hsk_sha256_final(&ctx, hash);

  goto done;

fail:
  ret = false;

done:
  for (j = 0; j < i; j++) {
    hsk_dns_raw_rr_t *raw = &records[j];

    if (raw->data)
      free(raw->data);
  }

  free(records);

  return ret;
}

bool
hsk_dns_msg_clean(hsk_dns_msg_t *msg, uint16_t type) {
  if (!msg)
    return false;

  if (!hsk_dns_rrs_clean(&msg->an, type))
    return false;

  if (!hsk_dns_rrs_clean(&msg->ns, type))
    return false;

  if (!hsk_dns_rrs_clean(&msg->ar, type))
    return false;

  return true;
}

bool
hsk_dns_rrs_clean(hsk_dns_rrs_t *rrs, uint16_t type) {
  if (!rrs)
    return false;

  hsk_dns_rrs_t *tmp = hsk_dns_rrs_alloc();

  if (!tmp)
    return false;

  int i;
  for (i = 0; i < rrs->size; i++) {
    hsk_dns_rr_t *rr = rrs->items[i];

    switch (rr->type) {
      case HSK_DNS_DS:
      case HSK_DNS_DLV:
      case HSK_DNS_DNSKEY:
      case HSK_DNS_RRSIG:
      case HSK_DNS_NXT:
      case HSK_DNS_NSEC:
      case HSK_DNS_NSEC3:
      case HSK_DNS_NSEC3PARAM:
        if (type != rr->type) {
          hsk_dns_rr_free(rr);
          rrs->items[i] = NULL;
          break;
        }
        // fall through
      default:
        assert(hsk_dns_rrs_push(tmp, rr));
        break;
    }
  }

  hsk_dns_rrs_init(rrs);

  for (i = 0; i < tmp->size; i++) {
    hsk_dns_rr_t *rr = tmp->items[i];
    assert(hsk_dns_rrs_push(rrs, rr));
  }

  free(tmp);

  return true;
}

/*
 * Helpers
 */

bool
hsk_dns_is_subdomain(const char *parent, const char *child) {
  int parent_count = hsk_dns_label_count(parent);
  int child_count = hsk_dns_label_count(child);

  // All domains are children of "."
  if (parent_count == 0)
    return true;

  if (parent_count > child_count)
    return false;

  uint8_t child_labels[child_count];
  hsk_dns_label_split(child, child_labels, child_count);

  char sub[HSK_DNS_MAX_NAME];
  hsk_dns_label_from2(child, child_labels, child_count, parent_count * -1, sub);

  return strcmp(sub, parent) == 0;
}

static int
raw_rr_cmp(const void *a, const void *b) {
  assert(a && b);

  hsk_dns_raw_rr_t *x = (hsk_dns_raw_rr_t *)a;
  hsk_dns_raw_rr_t *y = (hsk_dns_raw_rr_t *)b;

  uint8_t *xd = x->data;
  size_t xs = x->size;
  uint8_t *yd = y->data;
  size_t ys = y->size;

  assert(hsk_dns_name_parse(&xd, &xs, NULL, NULL) != -1);
  assert(hsk_dns_name_parse(&yd, &ys, NULL, NULL) != -1);

  assert(xs >= 10);
  assert(ys >= 10);

  xd += 10;
  xs -= 10;
  yd += 10;
  ys -= 10;

  size_t s = xs < ys ? xs : ys;

  int r = memcmp(xd, yd, s);

  if (r != 0)
    return r;

  if (xs < ys)
    return -1;

  if (xs > ys)
    return 1;

  return 0;
}

static bool
raw_rr_equal(const hsk_dns_raw_rr_t *a, const hsk_dns_raw_rr_t *b) {
  assert(a && b);

  if (a->size != b->size)
    return false;

  return memcmp(a->data, b->data, a->size) == 0;
}
