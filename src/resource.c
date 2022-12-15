#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "addr.h"
#include "base32.h"
#include "bio.h"
#include "dns.h"
#include "dnssec.h"
#include "error.h"
#include "resource.h"
#include "utils.h"

// NS SOA RRSIG NSEC DNSKEY
// Possibly add A, AAAA, and DS
static const uint8_t hsk_type_map[] = {
  0x00, 0x07, 0x22, 0x00, 0x00,
  0x00, 0x00, 0x03, 0x80
};

/*
 * Helpers
 */

static void
to_fqdn(char *name);

/*
 * Resource serialization version 0
 * Record types: read
 */

bool
hsk_ds_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_ds_record_t *rec
) {
  if (*data_len < 5)
    return false;

  uint8_t size = 0;
  read_u16be(data, data_len, &rec->key_tag);
  read_u8(data, data_len, &rec->algorithm);
  read_u8(data, data_len, &rec->digest_type);
  read_u8(data, data_len, &size);

  if (size > 64)
    return false;

  if (!read_bytes(data, data_len, rec->digest, size))
    return false;

  rec->digest_len = size;

  return true;
}

bool
hsk_ns_record_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  hsk_ns_record_t *rec
) {
  return hsk_dns_name_read(data, data_len, dmp, rec->name);
}

bool
hsk_glue4_record_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  hsk_glue4_record_t *rec
) {
  if (!hsk_dns_name_read(data, data_len, dmp, rec->name))
    return false;

  return read_bytes(data, data_len, rec->inet4, 4);
}

bool
hsk_glue6_record_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  hsk_glue6_record_t *rec
) {
  if (!hsk_dns_name_read(data, data_len, dmp, rec->name))
    return false;

  return read_bytes(data, data_len, rec->inet6, 16);
}

bool
hsk_synth4_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_synth4_record_t *rec
) {
  return read_bytes(data, data_len, rec->inet4, 4);
}

bool
hsk_synth6_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_synth6_record_t *rec
) {
  return read_bytes(data, data_len, rec->inet6, 16);
}

bool
hsk_txt_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_txt_record_t *rec
) {
  // Length of the array of strings
  uint8_t length = 0;
  if (!read_u8(data, data_len, &length))
    return false;

  hsk_dns_txts_t *txts = &rec->txts;
  txts->size = length;

  // Iterate through array
  int i;
  for (i = 0; i < length; i++) {
    hsk_dns_txt_t *txt = hsk_dns_txt_alloc();

    if(!txt)
      return false;

    txts->items[i] = txt;

    // Size of this string
    uint8_t size = 0;
    if (!read_u8(data, data_len, &size)) {
      hsk_dns_txt_free(txt);
      return false;
    }

    txt->data_len = size;

    // Copy string
    if(!read_bytes(data, data_len, txt->data, size)){
      hsk_dns_txt_free(txt);
      return false;
    }
  }

  return true;
}

void
hsk_record_init(hsk_record_t *r) {
  if (r == NULL)
    return;

  r->type = r->type;

  switch (r->type) {
    case HSK_DS: {
      hsk_ds_record_t *rec = (hsk_ds_record_t *)r;
      rec->key_tag = 0;
      rec->algorithm = 0;
      rec->digest_type = 0;
      rec->digest_len = 0;
      memset(rec->digest, 0, sizeof(rec->digest));
      break;
    }
    case HSK_NS: {
      hsk_ns_record_t *rec = (hsk_ns_record_t *)r;
      memset(rec->name, 0, sizeof(rec->name));
      break;
    }
    case HSK_GLUE4: {
      hsk_glue4_record_t *rec = (hsk_glue4_record_t *)r;
      memset(rec->name, 0, sizeof(rec->name));
      memset(rec->inet4, 0, sizeof(rec->inet4));
      break;
    }
    case HSK_GLUE6: {
      hsk_glue6_record_t *rec = (hsk_glue6_record_t *)r;
      memset(rec->name, 0, sizeof(rec->name));
      memset(rec->inet6, 0, sizeof(rec->inet6));
      break;
    }
    case HSK_SYNTH4: {
      hsk_synth4_record_t *rec = (hsk_synth4_record_t *)r;
      memset(rec->inet4, 0, sizeof(rec->inet4));
      break;
    }
    case HSK_SYNTH6: {
      hsk_synth6_record_t *rec = (hsk_synth6_record_t *)r;
      memset(rec->inet6, 0, sizeof(rec->inet6));
      break;
    }
    case HSK_TEXT: {
      hsk_txt_record_t *rec = (hsk_txt_record_t *)r;
      memset(&rec->txts, 0, sizeof(rec->txts));
      break;
    }
  }
}

hsk_record_t *
hsk_record_alloc(uint8_t type) {
  hsk_record_t *r = NULL;

  switch (type) {
    case HSK_DS: {
      r = (hsk_record_t *)malloc(sizeof(hsk_ds_record_t));
      break;
    }
    case HSK_NS: {
      r = (hsk_record_t *)malloc(sizeof(hsk_ns_record_t));
      break;
    }
    case HSK_GLUE4: {
      r = (hsk_record_t *)malloc(sizeof(hsk_glue4_record_t));
      break;
    }
    case HSK_GLUE6: {
      r = (hsk_record_t *)malloc(sizeof(hsk_glue6_record_t));
      break;
    }
    case HSK_SYNTH4: {
      r = (hsk_record_t *)malloc(sizeof(hsk_synth4_record_t));
      break;
    }
    case HSK_SYNTH6: {
      r = (hsk_record_t *)malloc(sizeof(hsk_synth6_record_t));
      break;
    }
    case HSK_TEXT: {
      r = (hsk_record_t *)malloc(sizeof(hsk_txt_record_t));
      break;
    }
    default: {
      // Unknown record type.
      return NULL;
    }
  }

  r->type = type;

  hsk_record_init(r);
  return r;
}

void
hsk_record_free(hsk_record_t *r) {
  if (r == NULL)
    return;

  switch (r->type) {
    case HSK_DS: {
      hsk_ds_record_t *rec = (hsk_ds_record_t *)r;
      free(rec);
      break;
    }
    case HSK_NS: {
      hsk_ns_record_t *rec = (hsk_ns_record_t *)r;
      free(rec);
      break;
    }
    case HSK_GLUE4: {
      hsk_glue4_record_t *rec = (hsk_glue4_record_t *)r;
      free(rec);
      break;
    }
    case HSK_GLUE6: {
      hsk_glue6_record_t *rec = (hsk_glue6_record_t *)r;
      free(rec);
      break;
    }
    case HSK_SYNTH4: {
      hsk_synth4_record_t *rec = (hsk_synth4_record_t *)r;
      free(rec);
      break;
    }
    case HSK_SYNTH6: {
      hsk_synth6_record_t *rec = (hsk_synth6_record_t *)r;
      free(rec);
      break;
    }
    case HSK_TEXT: {
      hsk_txt_record_t *rec = (hsk_txt_record_t *)r;

      int i;
      for (i = 0; i < rec->txts.size; i++)
        hsk_dns_txt_free(rec->txts.items[i]);
      free(rec);
      break;
    }
    default: {
      // Why are we freeing memory for an unknown record type?
      break;
    }
  }
}

void
hsk_resource_free(hsk_resource_t *res) {
  if (res == NULL)
    return;

  int i;

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *rec = res->records[i];
    hsk_record_free(rec);
  }

  free(res);
}

bool
hsk_record_read(
  uint8_t **data,
  size_t *data_len,
  uint8_t type,
  const hsk_dns_dmp_t *dmp,
  hsk_record_t **res
) {
  hsk_record_t *r = hsk_record_alloc(type);

  if (r == NULL)
    return false;

  switch (type) {
    case HSK_DS: {
      hsk_ds_record_t *rec = (hsk_ds_record_t *)r;
      hsk_ds_record_read(data, data_len, rec);
      break;
    }
    case HSK_NS: {
      hsk_ns_record_t *rec = (hsk_ns_record_t *)r;
      hsk_ns_record_read(data, data_len, dmp, rec);
      break;
    }
    case HSK_GLUE4: {
      hsk_glue4_record_t *rec = (hsk_glue4_record_t *)r;
      hsk_glue4_record_read(data, data_len, dmp, rec);
      break;
    }
    case HSK_GLUE6: {
      hsk_glue6_record_t *rec = (hsk_glue6_record_t *)r;
      hsk_glue6_record_read(data, data_len, dmp, rec);
      break;
    }
    case HSK_SYNTH4: {
      hsk_synth4_record_t *rec = (hsk_synth4_record_t *)r;
      hsk_synth4_record_read(data, data_len, rec);
      break;
    }
    case HSK_SYNTH6: {
      hsk_synth6_record_t *rec = (hsk_synth6_record_t *)r;
      hsk_synth6_record_read(data, data_len, rec);
      break;
    }
    case HSK_TEXT: {
      hsk_txt_record_t *rec = (hsk_txt_record_t *)r;
      hsk_txt_record_read(data, data_len, rec);
      break;
    }
    default: {
      // Unknown record type.
      free(r);
      return false;
    }
  }

  *res = r;

  return true;
}

bool
hsk_resource_decode(
  const uint8_t *data,
  size_t data_len,
  hsk_resource_t **resource
) {
  // Pointer to iterate through input resource data.
  uint8_t *dat = (uint8_t *)data;

  // Initialize DNS Message Compression by storing
  // a "copy" of the entire message for pointer reference.
  // See rfc1035 section 4.1.4
  hsk_dns_dmp_t dmp;
  dmp.msg = dat;
  dmp.msg_len = data_len;

  // Initialize response struct.
  hsk_resource_t *res = malloc(sizeof(hsk_resource_t));

  if (res == NULL)
    goto fail;

  res->version = 0;
  res->record_count = 0;
  memset(res->records, 0, sizeof(hsk_record_t *));

  // Copy version from input.
  if (!read_u8(&dat, &data_len, &res->version))
    goto fail;

  // Only version 0 is valid at this time.
  if (res->version != 0)
    goto fail;

  // TTL is always constant due to tree interval.
  res->ttl = HSK_DEFAULT_TTL;

  // The rest of the data is records, read until empty.
  int i = 0;
  while (data_len > 0) {
    // Get record type.
    uint8_t type;
    read_u8(&dat, &data_len, &type);

    // Read the body of the record.
    if (!hsk_record_read(&dat, &data_len, type, &dmp, &res->records[i]))
      goto fail;

    // Increment total amount of records in this resource.
    i++;
  }

  res->record_count = i;

  *resource = res;

  return true;

fail:
  hsk_resource_free(res);
  return false;
}

const hsk_record_t *
hsk_resource_get(const hsk_resource_t *res, uint8_t type) {
  int i;
  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *rec = res->records[i];
    if (rec->type == type)
      return rec;
  }
  return NULL;
}

bool
hsk_resource_has(const hsk_resource_t *res, uint8_t type) {
  return hsk_resource_get(res, type) != NULL;
}

bool
hsk_resource_has_ns(const hsk_resource_t *res) {
  int i;
  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *rec = res->records[i];
    if (rec->type >= HSK_NS && rec->type <= HSK_SYNTH6)
      return true;
  }
  return false;
}

static bool
hsk_resource_to_ns(
  const hsk_resource_t *res,
  const char *name,
  hsk_dns_rrs_t *an
) {
  int i;
  char nsname[HSK_DNS_MAX_NAME + 1];

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    bool synth = false;

    switch (c->type) {
      case HSK_SYNTH4:
      case HSK_SYNTH6:
        synth = true;
      case HSK_NS:
      case HSK_GLUE4:
      case HSK_GLUE6:
        break;
      default:
        continue;
    }

    if (synth) {
      // SYNTH records only actually contain an IP address
      // for the adiditonal section. The NS name must
      // be computed on the fly by encoding the IP into base32.
      char b32[29];

      if (c->type == HSK_SYNTH4)
        hsk_base32_encode_hex(c->inet4, 4, b32, false);
      else
        hsk_base32_encode_hex(c->inet6, 16, b32, false);

      // Magic pseudo-TLD can also be directly resolved by hnsd
      sprintf(nsname, "_%s._synth.", b32);
    } else {
      // NS and GLUE records have the NS names ready to go.
      assert(hsk_dns_name_is_fqdn(c->name));
      strcpy(nsname, c->name);
    }

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_NS);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_ns_rd_t *rd = rr->rd;
    strcpy(rd->ns, nsname);

    hsk_dns_rrs_push(an, rr);
  }

  return true;
}

static bool
hsk_resource_to_txt(
  const hsk_resource_t *res,
  const char *name,
  hsk_dns_rrs_t *an
) {
  int i;

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_TEXT)
      continue;

    hsk_txt_record_t *rec = (hsk_txt_record_t *)c;
    hsk_dns_txts_t *txts = &rec->txts;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_TXT);

    if (!rr)
      return false;

    rr->ttl = res->ttl;
    hsk_dns_rr_set_name(rr, name);

    hsk_dns_txt_rd_t *rd = rr->rd;

    int i;
    for (i = 0; i < txts->size; i++) {
      hsk_dns_txt_t *txt = hsk_dns_txt_alloc();

      if (!txt) {
        hsk_dns_rr_free(rr);
        return false;
      }

      hsk_dns_txt_t *item = txts->items[i]; 
      txt->data_len = item->data_len;
      assert(txt->data_len <= 255);

      memcpy(&txt->data[0], item->data, txt->data_len);
      hsk_dns_txts_push(&rd->txts, txt);
    }

    hsk_dns_rrs_push(an, rr);
  }

  return true;
}

static bool
hsk_resource_to_ds(
  const hsk_resource_t *res,
  const char *name,
  hsk_dns_rrs_t *an
) {
  int i;

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_DS)
      continue;

    hsk_ds_record_t *rec = (hsk_ds_record_t *)c;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_DS);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_ds_rd_t *rd = rr->rd;

    rd->key_tag = rec->key_tag;
    rd->algorithm = rec->algorithm;
    rd->digest_type = rec->digest_type;
    rd->digest_len = rec->digest_len;

    rd->digest = malloc(rec->digest_len);

    if (!rd->digest) {
      hsk_dns_rr_free(rr);
      return false;
    }

    memcpy(rd->digest, &rec->digest[0], rec->digest_len);

    hsk_dns_rrs_push(an, rr);
  }

  return true;
}

static bool
hsk_resource_to_glue(
  const hsk_resource_t *res,
  const char *tld,
  hsk_dns_rrs_t *an
) {
  int i;

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    switch (c->type) {
      case HSK_GLUE4: {
        if (!hsk_dns_is_subdomain(tld, c->name))
          break;

        hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_A);
        if (!rr)
          return false;

        hsk_dns_rr_set_name(rr, c->name);
        rr->ttl = res->ttl;

        hsk_dns_a_rd_t *rd = rr->rd;
        memcpy(&rd->addr[0], &c->inet4[0], 4);

        hsk_dns_rrs_push(an, rr);

        break;
      }
      case HSK_SYNTH4: {
        hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_A);
        if (!rr)
          return false;

        // Compute the base32 name from the SYNTH IP address.
        // We are bypassing the checks in hsk_dns_rr_set_name()
        // which should be fine because the name is being derived, not received.
        char b32[29];
        hsk_base32_encode_hex(c->inet4, 4, b32, false);
        sprintf(rr->name, "_%s._synth.", b32);

        rr->ttl = res->ttl;

        hsk_dns_a_rd_t *rd = rr->rd;
        memcpy(&rd->addr[0], &c->inet4[0], 4);

        hsk_dns_rrs_push(an, rr);

        break;
      }
      case HSK_GLUE6: {
        if (!hsk_dns_is_subdomain(tld, c->name))
          break;

        hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_AAAA);
        if (!rr)
          return false;

        hsk_dns_rr_set_name(rr, c->name);
        rr->ttl = res->ttl;

        hsk_dns_aaaa_rd_t *rd = rr->rd;
        memcpy(&rd->addr[0], &c->inet6[0], 16);

        hsk_dns_rrs_push(an, rr);

        break;
      }
      case HSK_SYNTH6: {
        hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_AAAA);
        if (!rr)
          return false;

        char b32[29];
        hsk_base32_encode_hex(c->inet6, 16, b32, false);
        sprintf(rr->name, "_%s._synth.", b32);

        rr->ttl = res->ttl;

        hsk_dns_aaaa_rd_t *rd = rr->rd;
        memcpy(&rd->addr[0], &c->inet6[0], 16);

        hsk_dns_rrs_push(an, rr);

        break;
      }
      default:
        continue;
    }
  }

  return true;
}

bool
hsk_resource_root_to_soa(hsk_dns_rrs_t *an) {
  hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_SOA);

  if (!rr)
    return false;

  rr->ttl = 86400;

  hsk_dns_rr_set_name(rr, ".");

  hsk_dns_soa_rd_t *rd = rr->rd;
  strcpy(rd->ns, ".");
  strcpy(rd->mbox, ".");

  uint32_t year;
  uint32_t month;
  uint32_t day;
  uint32_t hour;

  hsk_ymdh(&year, &month, &day, &hour);

  uint32_t y = year * 1e6;
  uint32_t m = month * 1e4;
  uint32_t d = day * 1e2;
  uint32_t h = hour;

  rd->serial = y + m + d + h;
  rd->refresh = 1800;
  rd->retry = 900;
  rd->expire = 604800;
  rd->minttl = 86400;

  hsk_dns_rrs_push(an, rr);

  return true;
}

static bool
hsk_resource_root_to_ns(hsk_dns_rrs_t *an) {
  hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_NS);

  if (!rr)
    return false;

  rr->ttl = 518400;
  hsk_dns_rr_set_name(rr, ".");

  hsk_dns_ns_rd_t *rd = rr->rd;
  strcpy(rd->ns, ".");

  hsk_dns_rrs_push(an, rr);

  return true;
}

static bool
hsk_resource_root_to_a(hsk_dns_rrs_t *an, const hsk_addr_t *addr) {
  if (!addr || !hsk_addr_is_ip4(addr))
    return true;

  const uint8_t *ip = hsk_addr_get_ip(addr);

  hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_A);

  if (!rr)
    return false;

  rr->ttl = 518400;

  hsk_dns_rr_set_name(rr, ".");

  hsk_dns_a_rd_t *rd = rr->rd;

  memcpy(&rd->addr[0], ip, 4);

  hsk_dns_rrs_push(an, rr);

  return true;
}

static bool
hsk_resource_root_to_aaaa(hsk_dns_rrs_t *an, const hsk_addr_t *addr) {
  if (!addr || !hsk_addr_is_ip6(addr))
    return true;

  const uint8_t *ip = hsk_addr_get_ip(addr);

  hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_AAAA);

  if (!rr)
    return false;

  rr->ttl = 518400;

  hsk_dns_rr_set_name(rr, ".");

  hsk_dns_aaaa_rd_t *rd = rr->rd;

  memcpy(&rd->addr[0], ip, 16);

  hsk_dns_rrs_push(an, rr);

  return true;
}

static bool
hsk_resource_root_to_dnskey(hsk_dns_rrs_t *an) {
  const hsk_dns_rr_t *ksk = hsk_dnssec_get_ksk();
  hsk_dns_rr_t *ksk_rr = hsk_dns_rr_clone(ksk);

  if (!ksk_rr)
    return false;

  hsk_dns_rrs_push(an, ksk_rr);

  const hsk_dns_rr_t *zsk = hsk_dnssec_get_zsk();
  hsk_dns_rr_t *zsk_rr = hsk_dns_rr_clone(zsk);

  if (!zsk_rr)
    return false;

  hsk_dns_rrs_push(an, zsk_rr);

  return true;
}

static bool
hsk_resource_root_to_ds(hsk_dns_rrs_t *an) {
  const hsk_dns_rr_t *ds = hsk_dnssec_get_ds();
  hsk_dns_rr_t *rr = hsk_dns_rr_clone(ds);

  if (!rr)
    return false;

  hsk_dns_rrs_push(an, rr);

  return true;
}

bool
hsk_resource_to_empty(
  const char *name,
  const uint8_t *type_map,
  size_t type_map_len,
  hsk_dns_rrs_t *an
) {
  hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_NSEC);

  if (!rr)
    return false;

  rr->ttl = 86400;

  hsk_dns_rr_set_name(rr, name);

  hsk_dns_nsec_rd_t *rd = rr->rd;

  strcpy(rd->next_domain, ".");
  rd->type_map = NULL;
  rd->type_map_len = 0;

  if (type_map) {
    uint8_t *buf = malloc(type_map_len);

    if (!buf) {
      hsk_dns_rr_free(rr);
      return false;
    }

    memcpy(buf, type_map, type_map_len);

    rd->type_map = buf;
    rd->type_map_len = type_map_len;
  }

  hsk_dns_rrs_push(an, rr);

  return true;
}

static bool
hsk_resource_root_to_nsec(hsk_dns_rrs_t *an) {
  hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_NSEC);

  if (!rr)
    return false;

  uint8_t *bitmap = malloc(sizeof(hsk_type_map));

  if (!bitmap) {
    hsk_dns_rr_free(rr);
    return false;
  }

  memcpy(bitmap, &hsk_type_map[0], sizeof(hsk_type_map));

  rr->ttl = 86400;

  hsk_dns_rr_set_name(rr, ".");

  hsk_dns_nsec_rd_t *rd = rr->rd;

  strcpy(rd->next_domain, ".");
  rd->type_map = bitmap;
  rd->type_map_len = sizeof(hsk_type_map);

  hsk_dns_rrs_push(an, rr);

  return true;
}

hsk_dns_msg_t *
hsk_resource_to_dns(const hsk_resource_t *rs, const char *name, uint16_t type) {
  assert(hsk_dns_name_is_fqdn(name));

  int labels = hsk_dns_label_count(name);

  if (labels == 0)
    return NULL;

  char tld[HSK_DNS_MAX_NAME];
  int tld_len = hsk_dns_label_from(name, -1, tld);

  // tld_len includes the final dot but not the \0
  if (tld_len > HSK_DNS_MAX_LABEL + 1)
    return NULL;

  hsk_dns_msg_t *msg = hsk_dns_msg_alloc();

  if (!msg)
    return NULL;

  hsk_dns_rrs_t *an = &msg->an; // answer
  hsk_dns_rrs_t *ns = &msg->ns; // authority
  hsk_dns_rrs_t *ar = &msg->ar; // additional

  // Referral.
  if (labels > 1) {
    if (hsk_resource_has_ns(rs)) {
      hsk_resource_to_ns(rs, tld, ns);
      hsk_resource_to_ds(rs, tld, ns);
      hsk_resource_to_glue(rs, tld, ar);
      if (!hsk_resource_has(rs, HSK_DS))
        hsk_dnssec_sign_zsk(ns, HSK_DNS_NS);
      else
        hsk_dnssec_sign_zsk(ns, HSK_DNS_DS);
    } else {
      // Needs SOA.
      // Empty proof:
      hsk_resource_to_empty(tld, NULL, 0, ns);
      hsk_dnssec_sign_zsk(ns, HSK_DNS_NSEC);
      hsk_resource_root_to_soa(ns);
      hsk_dnssec_sign_zsk(ns, HSK_DNS_SOA);
    }

    return msg;
  }

  // Record types actually on-chain for HNS TLDs.
  switch (type) {
    case HSK_DNS_DS:
      hsk_resource_to_ds(rs, name, an);
      hsk_dnssec_sign_zsk(an, HSK_DNS_DS);
      break;
    case HSK_DNS_NS:
      // Includes SYNTH and GLUE records.
      hsk_resource_to_ns(rs, name, ns);
      hsk_resource_to_glue(rs, name, ar);
      hsk_dnssec_sign_zsk(ns, HSK_DNS_NS);
      break;
    case HSK_DNS_TXT:
      hsk_resource_to_txt(rs, name, an);
      hsk_dnssec_sign_zsk(an, HSK_DNS_TXT);
      break;
  }

  if (an->size > 0)
    msg->flags |= HSK_DNS_AA;

  // Attempt to force a referral if we don't have an answer.
  if (an->size == 0 && ns->size == 0) {
    if (hsk_resource_has_ns(rs)) {
      hsk_resource_to_ns(rs, name, ns);
      hsk_resource_to_ds(rs, name, ns);
      hsk_resource_to_glue(rs, name, ar);
      if (!hsk_resource_has(rs, HSK_DS))
        hsk_dnssec_sign_zsk(ns, HSK_DNS_NS);
      else
        hsk_dnssec_sign_zsk(ns, HSK_DNS_DS);
    } else {
      // Needs SOA.
      // Empty proof:
      hsk_resource_to_empty(name, NULL, 0, ns);
      hsk_dnssec_sign_zsk(ns, HSK_DNS_NSEC);
      hsk_resource_root_to_soa(ns);
      hsk_dnssec_sign_zsk(ns, HSK_DNS_SOA);
    }
  }

  return msg;
}

hsk_dns_msg_t *
hsk_resource_root(uint16_t type, const hsk_addr_t *addr) {
  hsk_dns_msg_t *msg = hsk_dns_msg_alloc();

  if (!msg)
    return NULL;

  msg->flags |= HSK_DNS_AA;

  hsk_dns_rrs_t *an = &msg->an;
  hsk_dns_rrs_t *ns = &msg->ns;
  hsk_dns_rrs_t *ar = &msg->ar;

  switch (type) {
    case HSK_DNS_ANY:
    case HSK_DNS_NS:
      hsk_resource_root_to_ns(an);
      hsk_dnssec_sign_zsk(an, HSK_DNS_NS);

      if (hsk_addr_is_ip4(addr)) {
        hsk_resource_root_to_a(ar, addr);
        hsk_dnssec_sign_zsk(ar, HSK_DNS_A);
      }

      if (hsk_addr_is_ip6(addr)) {
        hsk_resource_root_to_aaaa(ar, addr);
        hsk_dnssec_sign_zsk(ar, HSK_DNS_AAAA);
      }

      break;
    case HSK_DNS_SOA:
      hsk_resource_root_to_soa(an);
      hsk_dnssec_sign_zsk(an, HSK_DNS_SOA);

      hsk_resource_root_to_ns(ns);
      hsk_dnssec_sign_zsk(ns, HSK_DNS_NS);

      if (hsk_addr_is_ip4(addr)) {
        hsk_resource_root_to_a(ar, addr);
        hsk_dnssec_sign_zsk(ar, HSK_DNS_A);
      }

      if (hsk_addr_is_ip6(addr)) {
        hsk_resource_root_to_aaaa(ar, addr);
        hsk_dnssec_sign_zsk(ar, HSK_DNS_AAAA);
      }

      break;
    case HSK_DNS_DNSKEY:
      hsk_resource_root_to_dnskey(an);
      hsk_dnssec_sign_ksk(an, HSK_DNS_DNSKEY);
      break;
    case HSK_DNS_DS:
      hsk_resource_root_to_ds(an);
      hsk_dnssec_sign_zsk(an, HSK_DNS_DS);
      break;
    default:
      // Empty Proof:
      // Show all the types that we signed.
      hsk_resource_root_to_nsec(ns);
      hsk_dnssec_sign_zsk(ns, HSK_DNS_NSEC);
      hsk_resource_root_to_soa(ns);
      hsk_dnssec_sign_zsk(ns, HSK_DNS_SOA);
      break;
  }

  return msg;
}

hsk_dns_msg_t *
hsk_resource_to_nx(void) {
  hsk_dns_msg_t *msg = hsk_dns_msg_alloc();

  if (!msg)
    return NULL;

  msg->code = HSK_DNS_NXDOMAIN;
  msg->flags |= HSK_DNS_AA;

  hsk_dns_rrs_t *ns = &msg->ns;

  // NX Proof:
  // Just make it look like an
  // empty zone for the NX proof.
  // It seems to fool unbound without
  // breaking anything.
  hsk_resource_root_to_nsec(ns);
  hsk_resource_root_to_nsec(ns);
  hsk_dnssec_sign_zsk(ns, HSK_DNS_NSEC);

  hsk_resource_root_to_soa(ns);
  hsk_dnssec_sign_zsk(ns, HSK_DNS_SOA);

  return msg;
}

hsk_dns_msg_t *
hsk_resource_to_servfail(void) {
  hsk_dns_msg_t *msg = hsk_dns_msg_alloc();

  if (!msg)
    return NULL;

  msg->code = HSK_DNS_SERVFAIL;

  return msg;
}

hsk_dns_msg_t *
hsk_resource_to_notimp(void) {
  hsk_dns_msg_t *msg = hsk_dns_msg_alloc();

  if (!msg)
    return NULL;

  msg->code = HSK_DNS_NOTIMP;

  return msg;
}

/*
 * Helpers
 */

static void
to_fqdn(char *name) {
  size_t len = strlen(name);
  assert(len <= 63);
  name[len] = '.';
  name[len + 1] = '\0';
}

bool
pointer_to_ip(const char *name, uint8_t *ip, uint16_t *family) {
  char label[HSK_DNS_MAX_LABEL + 1];
  size_t len = hsk_dns_label_get(name, 0, label);

  if (len < 2 || len > 29 || label[0] != '_')
    return false;

  int j = hsk_base32_decode_hex(&label[1], ip, false);
  assert(j);

  if (j == 4) {
    if (family)
      *family = HSK_DNS_A;
  } else if (j == 16) {
    if (family)
      *family = HSK_DNS_AAAA;
  } else {
    return false;
  }

  return true;
}

bool
hsk_resource_is_ptr(const char *name) {
  return pointer_to_ip(name, NULL, NULL);
}
