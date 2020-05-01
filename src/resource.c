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

static const uint8_t hsk_zero_inet4[4] = {
  0x00, 0x00, 0x00, 0x00
};

static const uint8_t hsk_zero_inet6[16] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

// NS SOA RRSIG NSEC DNSKEY
// Possibly add A, AAAA, and DS
static const uint8_t hsk_type_map[] = {
  0x00, 0x07, 0x22, 0x00, 0x00,
  0x00, 0x00, 0x03, 0x80
};

// A RRSIG NSEC
static const uint8_t hsk_type_map_a[] = {
  0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x03
};

// AAAA RRSIG NSEC
static const uint8_t hsk_type_map_aaaa[] = {
  0x00, 0x06, 0x00, 0x00, 0x00, 0x80, 0x00, 0x03
};

static void
to_fqdn(char *name);

static void
ip_size(const uint8_t *ip, size_t *s, size_t *l);

static size_t
ip_write(const uint8_t *ip, uint8_t *data);

static bool
ip_read(const uint8_t *data, uint8_t *ip);

static void
ip_to_b32(const hsk_target_t *target, char *dst);

static bool
b32_to_ip(const char *str, uint8_t *ip, uint16_t *family);

static bool
pointer_to_ip(const char *name, uint8_t *ip, uint16_t *family);

static bool
target_to_dns(const hsk_target_t *target, const char *name, char *host);

bool
hsk_resource_str_read(
  uint8_t **data,
  size_t *data_len,
  char *str,
  size_t limit
) {
  uint8_t size = 0;
  uint8_t *chunk;

  if (!read_u8(data, data_len, &size))
    return false;

  if (!slice_bytes(data, data_len, &chunk, size))
    return false;

  int real_size = 0;
  int i;

  for (i = 0; i < size; i++) {
    uint8_t ch = chunk[i];

    // No DEL.
    if (ch == 0x7f)
      return false;

    // Any non-printable character can screw.
    // Tab, line feed, and carriage return all valid.
    if (ch < 0x20
        && ch != 0x09
        && ch != 0x0a
        && ch != 0x0d) {
      return false;
    }

    real_size += 1;
  }

  if (real_size > limit)
    return false;

  char *s = str;
  for (i = 0; i < size; i++) {
    uint8_t ch = chunk[i];

    *s = ch;
    s += 1;
  }

  *s ='\0';

  return true;
}

bool
hsk_resource_target_read(
  uint8_t **data,
  size_t *data_len,
  uint8_t type,
  const hsk_dns_dmp_t *dmp,
  hsk_target_t *target
) {
  target->type = type;

  switch (type) {
    case HSK_INET4: {
      return read_bytes(data, data_len, target->inet4, 4);
    }
    case HSK_INET6: {
      uint8_t field;

      if (!read_u8(data, data_len, &field))
        return false;

      uint8_t start = field >> 4;
      uint8_t len = field & 0x0f;

      if (start + len > 16)
        return false;

      uint8_t left = 16 - (start + len);

      // Front half.
      if (!read_bytes(data, data_len, target->inet6, start))
        return false;

      // Fill in the missing section.
      memset(&target->inet6[start], 0x00, len);

      // Back half.
      uint8_t *back = &target->inet6[start + len];

      return read_bytes(data, data_len, back, left);
    }
    case HSK_ONION: {
      return read_bytes(data, data_len, target->onion, 10);
    }
    case HSK_ONIONNG: {
      return read_bytes(data, data_len, target->onion, 33);
    }
    case HSK_NAME: {
      return hsk_dns_name_read(data, data_len, &dmp, target->name);
    }
    default: {
      return false;
    }
  }
}

bool
hsk_resource_host_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  hsk_target_t *target
) {
  uint8_t type;

  if (!read_u8(data, data_len, &type))
    return false;

  if (type == HSK_GLUE) {
    if (!hsk_resource_target_read(data, data_len, HSK_NAME, dmp, target))
      return false;

    if (!hsk_resource_target_read(data, data_len, HSK_INET4, dmp, target))
      return false;

    if (!hsk_resource_target_read(data, data_len, HSK_INET6, dmp, target))
      return false;

    if (memcmp(target->inet4, hsk_zero_inet4, 4) == 0
        && memcmp(target->inet6, hsk_zero_inet6, 16) == 0) {
      return false;
    }

    target->type = HSK_GLUE;

    return true;
  }

  return hsk_resource_target_read(data, data_len, type, dmp, target);
}

bool
hsk_host_record_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  hsk_host_record_t *rec
) {
  return hsk_resource_host_read(data, data_len, dmp, &rec->target);
}

bool
hsk_txt_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_txt_record_t *rec
) {
  return hsk_resource_str_read(data, data_len, rec->text, 255);
}

bool
hsk_service_record_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  hsk_service_record_t *rec
) {
  if (!hsk_dns_name_read(data, data_len, &dmp, rec->service))
    return false;

  if (hsk_dns_label_count(rec->service) != 1)
    return false;

  if (!hsk_dns_name_read(data, data_len, &dmp, rec->protocol))
    return false;

  if (hsk_dns_label_count(rec->protocol) != 1)
    return false;

  if (!read_u8(data, data_len, &rec->priority))
    return false;

  if (!read_u8(data, data_len, &rec->weight))
    return false;

  if (!hsk_resource_host_read(data, data_len, dmp, &rec->target))
    return false;

  if (!read_u16be(data, data_len, &rec->port))
    return false;

  return true;
}

bool
hsk_location_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_location_record_t *rec
) {
  if (*data_len < 16)
    return false;

  read_u8(data, data_len, &rec->version);
  read_u8(data, data_len, &rec->size);
  read_u8(data, data_len, &rec->horiz_pre);
  read_u8(data, data_len, &rec->vert_pre);
  read_u32be(data, data_len, &rec->latitude);
  read_u32be(data, data_len, &rec->longitude);
  read_u32be(data, data_len, &rec->altitude);

  return true;
}

bool
hsk_magnet_record_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  hsk_magnet_record_t *rec
) {
  if (!hsk_dns_name_read(data, data_len, &dmp, rec->nid))
    return false;

  if (hsk_dns_label_count(rec->nid) != 1)
    return false;

  uint8_t size = 0;
  if (!read_u8(data, data_len, &size))
    return false;

  if (size > 64)
    return false;

  if (!read_bytes(data, data_len, rec->nin, size))
    return false;

  rec->nin_len = size;

  return true;
}

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
hsk_tls_record_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  hsk_tls_record_t *rec
) {
  if (!hsk_dns_name_read(data, data_len, &dmp, rec->protocol))
    return false;

  if (hsk_dns_label_count(rec->protocol) != 1)
    return false;

  if (*data_len < 6)
    return false;

  uint8_t size = 0;
  read_u16be(data, data_len, &rec->port);
  read_u8(data, data_len, &rec->usage);
  read_u8(data, data_len, &rec->selector);
  read_u8(data, data_len, &rec->matching_type);
  read_u8(data, data_len, &size);

  if (size > 64)
    return false;

  if (!read_bytes(data, data_len, rec->certificate, size))
    return false;

  rec->certificate_len = size;

  return true;
}

bool
hsk_smime_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_smime_record_t *rec
) {
  if (!read_bytes(data, data_len, rec->hash, 28))
    return false;

  if (*data_len < 4)
    return false;

  uint8_t size = 0;
  read_u8(data, data_len, &rec->usage);
  read_u8(data, data_len, &rec->selector);
  read_u8(data, data_len, &rec->matching_type);
  read_u8(data, data_len, &size);

  if (size > 64)
    return false;

  if (!read_bytes(data, data_len, rec->certificate, size))
    return false;

  rec->certificate_len = size;

  return true;
}

bool
hsk_ssh_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_ssh_record_t *rec
) {
  if (*data_len < 3)
    return false;

  uint8_t size = 0;
  read_u8(data, data_len, &rec->algorithm);
  read_u8(data, data_len, &rec->digest_type);
  read_u8(data, data_len, &size);

  if (size > 64)
    return false;

  if (!read_bytes(data, data_len, rec->fingerprint, size))
    return false;

  rec->fingerprint_len = size;

  return true;
}

bool
hsk_pgp_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_pgp_record_t *rec
) {
  if (!read_bytes(data, data_len, rec->hash, 28))
    return false;

  uint16_t size;

  if (!read_u16be(data, data_len, &size))
    return false;

  if (size > 512)
    return false;

  if (!read_bytes(data, data_len, rec->pubkey, size))
    return false;

  rec->pubkey_len = size;

  return true;
}

bool
hsk_addr_record_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  hsk_addr_record_t *rec
) {
  uint8_t ctype;

  if (!read_u8(data, data_len, &ctype))
    return false;

  rec->ctype = ctype;

  switch (ctype) {
    case 0: {
      if (!hsk_dns_name_read(data, data_len, &dmp, rec->currency))
        return false;

      if (hsk_dns_label_count(rec->currency) != 1)
        return false;

      uint8_t size = 0;

      if (!read_u8(data, data_len, &size))
        return false;

      if (!read_ascii(data, data_len, rec->address, size))
        return false;

      break;
    }
    case 1:
    case 2: { // HSK / BTC
      uint8_t field;

      if (!read_u8(data, data_len, &field))
        return false;

      rec->testnet = (field & 0x80) != 0;

      if (!read_u8(data, data_len, &rec->version))
        return false;

      uint8_t size = (field & 0x7f) + 1;

      if (size > 64)
        return false;

      if (!read_bytes(data, data_len, rec->hash, size))
        return false;

      rec->hash_len = size;

      if (ctype == 1)
        strcpy(rec->currency, "handshake.");
      else
        strcpy(rec->currency, "bitcoin.");

      break;
    }
    case 3: { // ETH
      strcpy(rec->currency, "ethereum.");

      if (!read_bytes(data, data_len, rec->hash, 20))
        return false;

      rec->hash_len = 20;

      break;
    }
    default: {
      return false;
    }
  }

  return true;
}

bool
hsk_extra_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_extra_record_t *rec
) {
  uint16_t size = 0;

  if (!read_u16be(data, data_len, &size))
    return false;

  if (!read_bytes(data, data_len, rec->data, size))
    return false;

  rec->data_len = size;

  return true;
}

void
hsk_record_init(hsk_record_t *r) {
  if (r == NULL)
    return;

  r->type = r->type;

  switch (r->type) {
    case HSK_INET4:
    case HSK_INET6:
    case HSK_ONION:
    case HSK_ONIONNG:
    case HSK_NAME:
    case HSK_CANONICAL:
    case HSK_DELEGATE:
    case HSK_NS: {
      hsk_host_record_t *rec = (hsk_host_record_t *)r;
      rec->target.type = 0;
      memset(rec->target.name, 0, sizeof(rec->target.name));
      memset(rec->target.inet4, 0, sizeof(rec->target.inet4));
      memset(rec->target.inet6, 0, sizeof(rec->target.inet6));
      memset(rec->target.onion, 0, sizeof(rec->target.onion));
      break;
    }
    case HSK_SERVICE: {
      hsk_service_record_t *rec = (hsk_service_record_t *)r;
      memset(rec->service, 0, sizeof(rec->service));
      memset(rec->protocol, 0, sizeof(rec->protocol));
      rec->priority = 0;
      rec->weight = 0;
      rec->target.type = 0;
      memset(rec->target.name, 0, sizeof(rec->target.name));
      memset(rec->target.inet4, 0, sizeof(rec->target.inet4));
      memset(rec->target.inet6, 0, sizeof(rec->target.inet6));
      memset(rec->target.onion, 0, sizeof(rec->target.onion));
      rec->port = 0;
      break;
    }
    case HSK_URI:
    case HSK_EMAIL:
    case HSK_TEXT: {
      hsk_txt_record_t *rec = (hsk_txt_record_t *)r;
      memset(rec->text, 0, sizeof(rec->text));
      break;
    }
    case HSK_LOCATION: {
      hsk_location_record_t *rec = (hsk_location_record_t *)r;
      rec->version = 0;
      rec->size = 0;
      rec->horiz_pre = 0;
      rec->vert_pre = 0;
      rec->latitude = 0;
      rec->longitude = 0;
      rec->altitude = 0;
      break;
    }
    case HSK_MAGNET: {
      hsk_magnet_record_t *rec = (hsk_magnet_record_t *)r;
      memset(rec->nid, 0, sizeof(rec->nid));
      rec->nin_len = 0;
      memset(rec->nin, 0, sizeof(rec->nin));
      break;
    }
    case HSK_DS: {
      hsk_ds_record_t *rec = (hsk_ds_record_t *)r;
      rec->key_tag = 0;
      rec->algorithm = 0;
      rec->digest_type = 0;
      rec->digest_len = 0;
      memset(rec->digest, 0, sizeof(rec->digest));
      break;
    }
    case HSK_TLS: {
      hsk_tls_record_t *rec = (hsk_tls_record_t *)r;
      memset(rec->protocol, 0, sizeof(rec->protocol));
      rec->port = 0;
      rec->usage = 0;
      rec->selector = 0;
      rec->matching_type = 0;
      rec->certificate_len = 0;
      memset(rec->certificate, 0, sizeof(rec->certificate));
      break;
    }
    case HSK_SMIME: {
      hsk_smime_record_t *rec = (hsk_smime_record_t *)r;
      memset(rec->hash, 0, sizeof(rec->hash));
      rec->usage = 0;
      rec->selector = 0;
      rec->matching_type = 0;
      rec->certificate_len = 0;
      memset(rec->certificate, 0, sizeof(rec->certificate));
      break;
    }
    case HSK_SSH: {
      hsk_ssh_record_t *rec = (hsk_ssh_record_t *)r;
      rec->algorithm = 0;
      rec->digest_type = 0;
      rec->fingerprint_len = 0;
      memset(rec->fingerprint, 0, sizeof(rec->fingerprint));
      break;
    }
    case HSK_PGP: {
      hsk_pgp_record_t *rec = (hsk_pgp_record_t *)r;
      rec->pubkey_len = 0;
      memset(rec->pubkey, 0, sizeof(rec->pubkey));
      break;
    }
    case HSK_ADDR: {
      hsk_addr_record_t *rec = (hsk_addr_record_t *)r;
      memset(rec->currency, 0, sizeof(rec->currency));
      memset(rec->address, 0, sizeof(rec->address));
      rec->ctype = 0;
      rec->testnet = false;
      rec->version = 0;
      rec->hash_len = 0;
      memset(rec->hash, 0, sizeof(rec->hash));
      break;
    }
    default: {
      hsk_extra_record_t *rec = (hsk_extra_record_t *)r;
      rec->rtype = 0;
      rec->data_len = 0;
      memset(rec->data, 0, sizeof(rec->data));
      break;
    }
  }
}

hsk_record_t *
hsk_record_alloc(uint8_t type) {
  hsk_record_t *r = NULL;

  switch (type) {
    case HSK_INET4:
    case HSK_INET6:
    case HSK_ONION:
    case HSK_ONIONNG:
    case HSK_NAME:
    case HSK_CANONICAL:
    case HSK_DELEGATE:
    case HSK_NS: {
      r = (hsk_record_t *)malloc(sizeof(hsk_host_record_t));
      break;
    }
    case HSK_SERVICE: {
      r = (hsk_record_t *)malloc(sizeof(hsk_service_record_t));
      break;
    }
    case HSK_URI:
    case HSK_EMAIL:
    case HSK_TEXT: {
      r = (hsk_record_t *)malloc(sizeof(hsk_txt_record_t));
      break;
    }
    case HSK_LOCATION: {
      r = (hsk_record_t *)malloc(sizeof(hsk_location_record_t));
      break;
    }
    case HSK_MAGNET: {
      r = (hsk_record_t *)malloc(sizeof(hsk_magnet_record_t));
      break;
    }
    case HSK_DS: {
      r = (hsk_record_t *)malloc(sizeof(hsk_ds_record_t));
      break;
    }
    case HSK_TLS: {
      r = (hsk_record_t *)malloc(sizeof(hsk_tls_record_t));
      break;
    }
    case HSK_SMIME: {
      r = (hsk_record_t *)malloc(sizeof(hsk_smime_record_t));
      break;
    }
    case HSK_SSH: {
      r = (hsk_record_t *)malloc(sizeof(hsk_ssh_record_t));
      break;
    }
    case HSK_PGP: {
      r = (hsk_record_t *)malloc(sizeof(hsk_pgp_record_t));
      break;
    }
    case HSK_ADDR: {
      r = (hsk_record_t *)malloc(sizeof(hsk_addr_record_t));
      break;
    }
    default: {
      r = (hsk_record_t *)malloc(sizeof(hsk_extra_record_t));
      break;
    }
  }

  if (r == NULL)
    return NULL;

  if (type == HSK_NAME)
    type = HSK_CANONICAL;

  r->type = type;

  hsk_record_init(r);
  return r;
}

void
hsk_record_free(hsk_record_t *r) {
  if (r == NULL)
    return;

  switch (r->type) {
    case HSK_INET4:
    case HSK_INET6:
    case HSK_ONION:
    case HSK_ONIONNG:
    case HSK_NAME:
    case HSK_CANONICAL:
    case HSK_DELEGATE:
    case HSK_NS: {
      hsk_host_record_t *rec = (hsk_host_record_t *)r;
      free(rec);
      break;
    }
    case HSK_SERVICE: {
      hsk_service_record_t *rec = (hsk_service_record_t *)r;
      free(rec);
      break;
    }
    case HSK_URI:
    case HSK_EMAIL:
    case HSK_TEXT: {
      hsk_txt_record_t *rec = (hsk_txt_record_t *)r;
      free(rec);
      break;
    }
    case HSK_LOCATION: {
      hsk_location_record_t *rec = (hsk_location_record_t *)r;
      free(rec);
      break;
    }
    case HSK_MAGNET: {
      hsk_magnet_record_t *rec = (hsk_magnet_record_t *)r;
      free(rec);
      break;
    }
    case HSK_DS: {
      hsk_ds_record_t *rec = (hsk_ds_record_t *)r;
      free(rec);
      break;
    }
    case HSK_TLS: {
      hsk_tls_record_t *rec = (hsk_tls_record_t *)r;
      free(rec);
      break;
    }
    case HSK_SMIME: {
      hsk_smime_record_t *rec = (hsk_smime_record_t *)r;
      free(rec);
      break;
    }
    case HSK_SSH: {
      hsk_ssh_record_t *rec = (hsk_ssh_record_t *)r;
      free(rec);
      break;
    }
    case HSK_PGP: {
      hsk_pgp_record_t *rec = (hsk_pgp_record_t *)r;
      free(rec);
      break;
    }
    case HSK_ADDR: {
      hsk_addr_record_t *rec = (hsk_addr_record_t *)r;
      free(rec);
      break;
    }
    default: {
      hsk_extra_record_t *rec = (hsk_extra_record_t *)r;
      free(rec);
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

  bool result = true;

  switch (type) {
    case HSK_INET4:
    case HSK_INET6:
    case HSK_ONION:
    case HSK_ONIONNG:
    case HSK_NAME: {
      hsk_host_record_t *rec = (hsk_host_record_t *)r;
      result = hsk_resource_target_read(data, data_len, type, dmp, &rec->target);
      break;
    }
    case HSK_CANONICAL:
    case HSK_DELEGATE:
    case HSK_NS: {
      hsk_host_record_t *rec = (hsk_host_record_t *)r;
      result = hsk_host_record_read(data, data_len, dmp, rec);
      break;
    }
    case HSK_SERVICE: {
      hsk_service_record_t *rec = (hsk_service_record_t *)r;
      result = hsk_service_record_read(data, data_len, dmp, rec);
      break;
    }
    case HSK_URI:
    case HSK_EMAIL:
    case HSK_TEXT: {
      hsk_txt_record_t *rec = (hsk_txt_record_t *)r;
      result = hsk_txt_record_read(data, data_len, rec);
      break;
    }
    case HSK_LOCATION: {
      hsk_location_record_t *rec = (hsk_location_record_t *)r;
      result = hsk_location_record_read(data, data_len, rec);
      break;
    }
    case HSK_MAGNET: {
      hsk_magnet_record_t *rec = (hsk_magnet_record_t *)r;
      result = hsk_magnet_record_read(data, data_len, dmp, rec);
      break;
    }
    case HSK_DS: {
      hsk_ds_record_t *rec = (hsk_ds_record_t *)r;
      result = hsk_ds_record_read(data, data_len, rec);
      break;
    }
    case HSK_TLS: {
      hsk_tls_record_t *rec = (hsk_tls_record_t *)r;
      result = hsk_tls_record_read(data, data_len, dmp, rec);
      break;
    }
    case HSK_SMIME: {
      hsk_smime_record_t *rec = (hsk_smime_record_t *)r;
      result = hsk_smime_record_read(data, data_len, rec);
      break;
    }
    case HSK_SSH: {
      hsk_ssh_record_t *rec = (hsk_ssh_record_t *)r;
      result = hsk_ssh_record_read(data, data_len, rec);
      break;
    }
    case HSK_PGP: {
      hsk_pgp_record_t *rec = (hsk_pgp_record_t *)r;
      result = hsk_pgp_record_read(data, data_len, rec);
      break;
    }
    case HSK_ADDR: {
      hsk_addr_record_t *rec = (hsk_addr_record_t *)r;
      result = hsk_addr_record_read(data, data_len, dmp, rec);
      break;
    }
    default: {
      hsk_extra_record_t *rec = (hsk_extra_record_t *)r;
      result = hsk_extra_record_read(data, data_len, rec);
      break;
    }
  }

  if (!result) {
    free(r);
    return false;
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
  uint8_t *dat = (uint8_t *)data;

  hsk_dns_dmp_t dmp;
  dmp.msg = dat;
  dmp.msg_len = data_len;

  hsk_resource_t *res = malloc(sizeof(hsk_resource_t));

  if (res == NULL)
    goto fail;

  res->version = 0;
  res->compat = false;
  res->ttl = 0;
  res->record_count = 0;
  memset(res->records, 0, sizeof(hsk_record_t *));

  if (!read_u8(&dat, &data_len, &res->version))
    goto fail;

  if (res->version != 0)
    goto fail;

  uint16_t field;
  if (!read_u16be(&dat, &data_len, &field))
    goto fail;

  res->compat = (field & 0x8000) != 0;
  res->ttl = ((uint32_t)(field & 0x7fff)) << 6;

  if (res->ttl == 0)
    res->ttl = 1 << 6;

  // Read records.
  for (i = 0; i < 255; i++) {
    if (data_len <= 0)
      break;

    uint8_t type;

    read_u8(&dat, &data_len, &type);

    if (!hsk_record_read(&dat, &data_len, type, &dmp, &res->records[i]))
      goto fail;
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

static bool
hsk_resource_to_a(
  const hsk_resource_t *res,
  const char *name,
  hsk_dns_rrs_t *an
) {
  int i;

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_INET4)
      continue;

    hsk_inet4_record_t *rec = (hsk_inet4_record_t *)c;
    hsk_target_t *target = &rec->target;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_A);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_a_rd_t *rd = rr->rd;
    memcpy(&rd->addr[0], &target->inet4[0], 4);

    hsk_dns_rrs_push(an, rr);
  }

  return true;
}

static bool
hsk_resource_to_aaaa(
  const hsk_resource_t *res,
  const char *name,
  hsk_dns_rrs_t *an
) {
  int i;

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_INET6)
      continue;

    hsk_inet6_record_t *rec = (hsk_inet6_record_t *)c;
    hsk_target_t *target = &rec->target;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_AAAA);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_aaaa_rd_t *rd = rr->rd;
    memcpy(&rd->addr[0], &target->inet6[0], 16);

    hsk_dns_rrs_push(an, rr);
  }

  return true;
}

static bool
hsk_resource_to_cname(
  const hsk_resource_t *res,
  const char *name,
  hsk_dns_rrs_t *an
) {
  int i;
  char cname[HSK_DNS_MAX_NAME + 1];

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_CANONICAL)
      continue;

    hsk_canonical_record_t *rec = (hsk_canonical_record_t *)c;
    hsk_target_t *target = &rec->target;

    if (target->type != HSK_NAME && target->type != HSK_GLUE)
      continue;

    if (!target_to_dns(target, name, cname))
      continue;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_CNAME);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_cname_rd_t *rd = rr->rd;
    strcpy(rd->target, cname);

    hsk_dns_rrs_push(an, rr);
  }

  return true;
}

static bool
hsk_resource_to_dname(
  const hsk_resource_t *res,
  const char *name,
  hsk_dns_rrs_t *an
) {
  int i;
  char dname[HSK_DNS_MAX_NAME + 1];

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_DELEGATE)
      continue;

    hsk_delegate_record_t *rec = (hsk_delegate_record_t *)c;
    hsk_target_t *target = &rec->target;

    if (target->type != HSK_NAME && target->type != HSK_GLUE)
      continue;

    if (!target_to_dns(target, name, dname))
      continue;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_DNAME);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_dname_rd_t *rd = rr->rd;
    strcpy(rd->target, dname);

    hsk_dns_rrs_push(an, rr);
  }

  return true;
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

    if (c->type != HSK_NS)
      continue;

    hsk_ns_record_t *rec = (hsk_ns_record_t *)c;
    hsk_target_t *target = &rec->target;

    if (!target_to_dns(target, name, nsname))
      continue;

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
hsk_resource_to_nsip(
  const hsk_resource_t *res,
  const char *name,
  hsk_dns_rrs_t *ar
) {
  int i;
  char ptr[HSK_DNS_MAX_NAME + 1];

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_NS)
      continue;

    hsk_ns_record_t *rec = (hsk_ns_record_t *)c;
    hsk_target_t *target = &rec->target;

    if (target->type != HSK_INET4 && target->type != HSK_INET6)
      continue;

    if (!target_to_dns(target, name, ptr))
      continue;

    uint16_t rrtype = HSK_DNS_A;

    if (target->type == HSK_INET6)
      rrtype = HSK_DNS_AAAA;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(rrtype);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, ptr);
    rr->ttl = res->ttl;

    if (rrtype == HSK_DNS_A) {
      hsk_dns_a_rd_t *rd = rr->rd;
      memcpy(&rd->addr[0], &target->inet4[0], 4);
    } else {
      hsk_dns_aaaa_rd_t *rd = rr->rd;
      memcpy(&rd->addr[0], &target->inet6[0], 16);
    }

    hsk_dns_rrs_push(ar, rr);
  }

  return true;
}

static bool
hsk_resource_to_srvip(
  const hsk_resource_t *res,
  const char *name,
  const char *protocol,
  const char *service,
  hsk_dns_rrs_t *ar
) {
  int i;
  char ptr[HSK_DNS_MAX_NAME + 1];

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_SERVICE)
      continue;

    hsk_service_record_t *rec = (hsk_service_record_t *)c;
    hsk_target_t *target = &rec->target;

    if (target->type != HSK_INET4 && target->type != HSK_INET6)
      continue;

    if (strcasecmp(protocol, rec->protocol) != 0)
      continue;

    if (strcasecmp(service, rec->service) != 0)
      continue;

    if (!target_to_dns(target, name, ptr))
      continue;

    uint16_t rrtype = HSK_DNS_A;

    if (target->type == HSK_INET6)
      rrtype = HSK_DNS_AAAA;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(rrtype);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, ptr);
    rr->ttl = res->ttl;

    if (rrtype == HSK_DNS_A) {
      hsk_dns_a_rd_t *rd = rr->rd;
      memcpy(&rd->addr[0], &target->inet4[0], 4);
    } else {
      hsk_dns_aaaa_rd_t *rd = rr->rd;
      memcpy(&rd->addr[0], &target->inet6[0], 16);
    }

    hsk_dns_rrs_push(ar, rr);
  }

  return true;
}

static bool
hsk_resource_to_mx(
  const hsk_resource_t *res,
  const char *name,
  hsk_dns_rrs_t *an
) {
  int i;
  char mx[HSK_DNS_MAX_NAME + 1];

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_SERVICE)
      continue;

    hsk_service_record_t *rec = (hsk_service_record_t *)c;
    hsk_target_t *target = &rec->target;

    if (strcasecmp(rec->service, "smtp.") != 0
        || strcasecmp(rec->protocol, "tcp.") != 0) {
      continue;
    }

    if (!target_to_dns(target, name, mx))
      continue;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_MX);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_mx_rd_t *rd = rr->rd;
    rd->preference = rec->priority;
    strcpy(rd->mx, mx);

    hsk_dns_rrs_push(an, rr);
  }

  return true;
}

static bool
hsk_resource_to_mxip(
  const hsk_resource_t *res,
  const char *name,
  hsk_dns_rrs_t *an
) {
  return hsk_resource_to_srvip(res, name, "tcp.", "smtp.", an);
}

static bool
hsk_resource_to_srv(
  const hsk_resource_t *res,
  const char *name,
  const char *protocol,
  const char *service,
  hsk_dns_rrs_t *an
) {
  int i;
  char host[HSK_DNS_MAX_NAME + 1];

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_SERVICE)
      continue;

    hsk_service_record_t *rec = (hsk_service_record_t *)c;
    hsk_target_t *target = &rec->target;

    if (strcasecmp(protocol, rec->protocol) != 0)
      continue;

    if (strcasecmp(service, rec->service) != 0)
      continue;

    if (!target_to_dns(target, name, host))
      continue;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_SRV);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_srv_rd_t *rd = rr->rd;

    rd->priority = rec->priority;
    rd->weight = rec->weight;
    rd->port = rec->port;
    strcpy(rd->target, host);

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

    hsk_text_record_t *rec = (hsk_text_record_t *)c;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_TXT);

    if (!rr)
      return false;

    rr->ttl = res->ttl;
    hsk_dns_rr_set_name(rr, name);

    hsk_dns_txt_rd_t *rd = rr->rd;

    hsk_dns_txt_t *txt = hsk_dns_txt_alloc();

    if (!txt) {
      hsk_dns_rr_free(rr);
      return false;
    }

    txt->data_len = strlen(rec->text);
    assert(txt->data_len <= 255);

    memcpy(&txt->data[0], rec->text, txt->data_len);

    hsk_dns_txts_push(&rd->txts, txt);

    hsk_dns_rrs_push(an, rr);
  }

  return true;
}

static bool
hsk_resource_to_loc(
  const hsk_resource_t *res,
  const char *name,
  hsk_dns_rrs_t *an
) {
  int i;

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_LOCATION)
      continue;

    hsk_location_record_t *rec = (hsk_location_record_t *)c;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_LOC);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_loc_rd_t *rd = rr->rd;

    rd->version = rec->version;
    rd->size = rec->size;
    rd->horiz_pre = rec->horiz_pre;
    rd->vert_pre = rec->vert_pre;
    rd->latitude = rec->latitude;
    rd->longitude = rec->longitude;
    rd->altitude = rec->altitude;

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
hsk_resource_to_tlsa(
  const hsk_resource_t *res,
  const char *name,
  const char *protocol,
  uint16_t port,
  hsk_dns_rrs_t *an
) {
  int i;

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_TLS)
      continue;

    hsk_tls_record_t *rec = (hsk_tls_record_t *)c;

    if (strcasecmp(protocol, rec->protocol) != 0)
      continue;

    if (port != rec->port)
      continue;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_TLSA);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_tlsa_rd_t *rd = rr->rd;

    rd->usage = rec->usage;
    rd->selector = rec->selector;
    rd->matching_type = rec->matching_type;
    rd->certificate_len = rec->certificate_len;

    rd->certificate = malloc(rec->certificate_len);

    if (!rd->certificate) {
      hsk_dns_rr_free(rr);
      return false;
    }

    memcpy(rd->certificate, &rec->certificate[0], rec->certificate_len);

    hsk_dns_rrs_push(an, rr);
  }

  return true;
}

static bool
hsk_resource_to_smimea(
  const hsk_resource_t *res,
  const char *name,
  const uint8_t *hash,
  hsk_dns_rrs_t *an
) {
  int i;

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_SMIME)
      continue;

    hsk_smime_record_t *rec = (hsk_smime_record_t *)c;

    if (memcmp(hash, rec->hash, 28) != 0)
      continue;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_SMIMEA);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_smimea_rd_t *rd = rr->rd;

    rd->usage = rec->usage;
    rd->selector = rec->selector;
    rd->matching_type = rec->matching_type;
    rd->certificate_len = rec->certificate_len;

    rd->certificate = malloc(rec->certificate_len);

    if (!rd->certificate) {
      hsk_dns_rr_free(rr);
      return false;
    }

    memcpy(rd->certificate, &rec->certificate[0], rec->certificate_len);

    hsk_dns_rrs_push(an, rr);
  }

  return true;
}

static bool
hsk_resource_to_sshfp(
  const hsk_resource_t *res,
  const char *name,
  hsk_dns_rrs_t *an
) {
  int i;

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_SSH)
      continue;

    hsk_ssh_record_t *rec = (hsk_ssh_record_t *)c;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_SSHFP);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_sshfp_rd_t *rd = rr->rd;

    rd->algorithm = rec->algorithm;
    rd->digest_type = rec->digest_type;
    rd->fingerprint_len = rec->fingerprint_len;

    rd->fingerprint = malloc(rec->fingerprint_len);

    if (!rd->fingerprint) {
      hsk_dns_rr_free(rr);
      return false;
    }

    memcpy(rd->fingerprint, &rec->fingerprint[0], rec->fingerprint_len);

    hsk_dns_rrs_push(an, rr);
  }

  return true;
}

static bool
hsk_resource_to_openpgpkey(
  const hsk_resource_t *res,
  const char *name,
  const uint8_t *hash,
  hsk_dns_rrs_t *an
) {
  int i;

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_PGP)
      continue;

    hsk_pgp_record_t *rec = (hsk_pgp_record_t *)c;

    if (memcmp(hash, rec->hash, 28) != 0)
      continue;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_OPENPGPKEY);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_openpgpkey_rd_t *rd = rr->rd;
    rd->pubkey_len = rec->pubkey_len;

    rd->pubkey = malloc(rec->pubkey_len);

    if (!rd->pubkey) {
      hsk_dns_rr_free(rr);
      return false;
    }

    memcpy(rd->pubkey, &rec->pubkey[0], rec->pubkey_len);

    hsk_dns_rrs_push(an, rr);
  }

  return true;
}

static bool
hsk_resource_to_uri(
  const hsk_resource_t *res,
  const char *name,
  hsk_dns_rrs_t *an
) {
  int i;

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_URI)
      continue;

    hsk_uri_record_t *rec = (hsk_uri_record_t *)c;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_URI);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_uri_rd_t *rd = rr->rd;

    rd->priority = 0;
    rd->weight = 0;
    rd->data_len = strlen(rec->text);

    assert(rd->data_len <= 255);

    memcpy(&rd->data[0], &rec->text[0], rd->data_len);

    hsk_dns_rrs_push(an, rr);
  }

  char nid[HSK_DNS_MAX_LABEL + 1];
  char nin[HSK_DNS_MAX_NAME + 1];

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_MAGNET)
      continue;

    hsk_magnet_record_t *rec = (hsk_magnet_record_t *)c;

    size_t nid_len = hsk_dns_label_get(rec->nid, 0, nid);
    hsk_to_lower(nid);

    size_t len = 16 + nid_len + rec->nin_len * 2;

    if (len + 1 > 255)
      continue;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_URI);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    assert(rec->nin_len <= 64);
    hsk_hex_encode(rec->nin, rec->nin_len, nin);

    hsk_dns_uri_rd_t *rd = rr->rd;

    rd->priority = 0;
    rd->weight = 0;
    rd->data_len = len;

    assert(rd->data_len <= 255);

    sprintf((char *)rd->data, "magnet:?xt=urn:%s:%s", nid, nin);

    hsk_dns_rrs_push(an, rr);
  }

  char *currency = &nid[0];
  char *addr = &nin[0];

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_ADDR)
      continue;

    hsk_addr_record_t *rec = (hsk_addr_record_t *)c;

    if (rec->ctype != 0 && rec->ctype != 3)
      continue;

    size_t currency_len = hsk_dns_label_get(rec->currency, 0, currency);
    hsk_to_lower(currency);

    size_t addr_len = 0;

    if (rec->ctype == 0) {
      addr_len = strlen(rec->address);
      memcpy(addr, rec->address, addr_len);
    } else if (rec->ctype == 3) {
      assert(rec->hash_len <= 64);
      addr_len = 2 + rec->hash_len * 2;
      addr[0] = '0';
      addr[1] = 'x';
      hsk_hex_encode(rec->hash, rec->hash_len, &addr[2]);
    } else {
      assert(0);
    }

    size_t len = currency_len + 1 + addr_len;

    if (len + 1 > 255)
      continue;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_URI);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_uri_rd_t *rd = rr->rd;

    rd->priority = 0;
    rd->weight = 0;
    rd->data_len = len;

    assert(rd->data_len <= 255);

    sprintf((char *)rd->data, "%s:%s", currency, addr);

    hsk_dns_rrs_push(an, rr);
  }

  return true;
}

static bool
hsk_resource_to_rp(
  const hsk_resource_t *res,
  const char *name,
  hsk_dns_rrs_t *an
) {
  char mbox[HSK_DNS_MAX_NAME + 2];
  int i;

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];

    if (c->type != HSK_EMAIL)
      continue;

    hsk_email_record_t *rec = (hsk_email_record_t *)c;

    if (strlen(rec->text) > 63)
      continue;

    sprintf(mbox, "%s.", rec->text);

    if (!hsk_dns_name_verify(mbox))
      continue;

    hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_RP);

    if (!rr)
      return false;

    hsk_dns_rr_set_name(rr, name);
    rr->ttl = res->ttl;

    hsk_dns_rp_rd_t *rd = rr->rd;

    strcpy(rd->mbox, mbox);
    strcpy(rd->txt, ".");

    hsk_dns_rrs_push(an, rr);
  }

  return true;
}

static bool
hsk_resource_to_glue(
  const hsk_resource_t *res,
  hsk_dns_rrs_t *an,
  uint16_t rrtype
) {
  int i;

  for (i = 0; i < res->record_count; i++) {
    hsk_record_t *c = res->records[i];
    hsk_target_t *target;

    switch (c->type) {
      case HSK_CANONICAL: {
        if (rrtype != HSK_DNS_CNAME)
          continue;

        break;
      }
      case HSK_DELEGATE: {
        if (rrtype != HSK_DNS_DNAME)
          continue;

        break;
      }
      case HSK_NS: {
        if (rrtype != HSK_DNS_NS)
          continue;

        break;
      }
      case HSK_SERVICE: {
        if (rrtype != HSK_DNS_SRV && rrtype != HSK_DNS_MX)
          continue;

        if (rrtype == HSK_DNS_MX) {
          hsk_service_record_t *rec = (hsk_service_record_t *)c;

          if (strcasecmp(rec->service, "smtp.") != 0
              || strcasecmp(rec->protocol, "tcp.") != 0) {
            continue;
          }
        }

        break;
      }
      default: {
        continue;
      }
    }

    switch (c->type) {
      case HSK_CANONICAL:
      case HSK_DELEGATE:
      case HSK_NS: {
        hsk_host_record_t *rec = (hsk_host_record_t *)c;
        target = &rec->target;
        break;
      }
      case HSK_SERVICE: {
        hsk_service_record_t *rec = (hsk_service_record_t *)c;
        target = &rec->target;
        break;
      }
      default: {
        continue;
      }
    }

    if (target->type != HSK_GLUE)
      continue;

    if (memcmp(target->inet4, hsk_zero_inet4, 4) != 0) {
      hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_A);

      if (!rr)
        return false;

      hsk_dns_rr_set_name(rr, target->name);
      rr->ttl = res->ttl;

      hsk_dns_a_rd_t *rd = rr->rd;
      memcpy(&rd->addr[0], &target->inet4[0], 4);

      hsk_dns_rrs_push(an, rr);
    }

    if (memcmp(target->inet6, hsk_zero_inet6, 16) != 0) {
      hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_AAAA);

      if (!rr)
        return false;

      hsk_dns_rr_set_name(rr, target->name);
      rr->ttl = res->ttl;

      hsk_dns_aaaa_rd_t *rd = rr->rd;
      memcpy(&rd->addr[0], &target->inet6[0], 16);

      hsk_dns_rrs_push(an, rr);
    }
  }

  return true;
}

static bool
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

static bool
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

  hsk_dns_msg_t *msg = hsk_dns_msg_alloc();

  if (!msg)
    return NULL;

  hsk_dns_rrs_t *an = &msg->an;
  hsk_dns_rrs_t *ns = &msg->ns;
  hsk_dns_rrs_t *ar = &msg->ar;

  // Handle reverse pointers.
  if (labels == 2) {
    uint8_t ip[16];
    uint16_t family;

    if (pointer_to_ip(name, ip, &family)) {
      bool match = false;

      switch (type) {
        case HSK_DNS_ANY:
          match = true;
          break;
        case HSK_DNS_A:
          match = family == HSK_INET4;
          break;
        case HSK_DNS_AAAA:
          match = family == HSK_INET6;
          break;
      }

      if (!match) {
        // Needs SOA.
        // TODO: Make the reverse pointers TLDs.
        // Empty proof:
        if (family == HSK_INET4) {
          hsk_resource_to_empty(
            name,
            hsk_type_map_a,
            sizeof(hsk_type_map_a),
            ns
          );
        } else {
          hsk_resource_to_empty(
            name,
            hsk_type_map_aaaa,
            sizeof(hsk_type_map_aaaa),
            ns
          );
        }
        hsk_dnssec_sign_zsk(ns, HSK_DNS_NSEC);
        hsk_resource_root_to_soa(ns);
        hsk_dnssec_sign_zsk(ns, HSK_DNS_SOA);
        return msg;
      }

      uint16_t rrtype = HSK_DNS_A;

      if (family == HSK_INET6)
        rrtype = HSK_DNS_AAAA;

      msg->flags |= HSK_DNS_AA;

      hsk_dns_rr_t *rr = hsk_dns_rr_create(rrtype);

      if (!rr) {
        hsk_dns_msg_free(msg);
        return NULL;
      }

      rr->ttl = rs->ttl;
      hsk_dns_rr_set_name(rr, name);

      if (family == HSK_INET4) {
        hsk_dns_a_rd_t *rd = rr->rd;
        memcpy(&rd->addr[0], &ip[0], 4);
      } else {
        hsk_dns_aaaa_rd_t *rd = rr->rd;
        memcpy(&rd->addr[0], &ip[0], 16);
      }

      hsk_dns_rrs_push(an, rr);

      hsk_dnssec_sign_zsk(ar, rrtype);

      return msg;
    }
  }

  // Handle SRV, TLSA, and SMIMEA.
  if (labels == 3) {
    switch (type) {
      case HSK_DNS_SRV: {
        char protocol[HSK_DNS_MAX_LABEL + 2];
        char service[HSK_DNS_MAX_LABEL + 2];
        bool is_srv = hsk_dns_label_decode_srv(name, protocol, service);

        if (is_srv) {
          to_fqdn(protocol);
          to_fqdn(service);
          hsk_resource_to_srv(rs, name, protocol, service, an);
          hsk_resource_to_srvip(rs, name, protocol, service, ar);
          hsk_resource_to_glue(rs, ar, HSK_DNS_SRV);
          hsk_dnssec_sign_zsk(an, HSK_DNS_SRV);
        }

        break;
      }
      case HSK_DNS_TLSA: {
        char protocol[HSK_DNS_MAX_LABEL + 2];
        uint16_t port;
        bool is_tlsa = hsk_dns_label_decode_tlsa(name, protocol, &port);

        if (is_tlsa) {
          to_fqdn(protocol);
          hsk_resource_to_tlsa(rs, name, protocol, port, an);
          hsk_dnssec_sign_zsk(an, HSK_DNS_TLSA);
        }

        break;
      }
      case HSK_DNS_SMIMEA: {
        uint8_t hash[28];
        bool is_smimea = hsk_dns_label_decode_smimea(name, hash);

        if (is_smimea) {
          hsk_resource_to_smimea(rs, name, hash, an);
          hsk_dnssec_sign_zsk(an, HSK_DNS_SMIMEA);
        }

        break;
      }
      case HSK_DNS_OPENPGPKEY: {
        uint8_t hash[28];
        bool is_openpgpkey = hsk_dns_label_decode_openpgpkey(name, hash);

        if (is_openpgpkey) {
          hsk_resource_to_openpgpkey(rs, name, hash, an);
          hsk_dnssec_sign_zsk(an, HSK_DNS_OPENPGPKEY);
        }

        break;
      }
    }

    if (an->size > 0) {
      msg->flags |= HSK_DNS_AA;
      return msg;
    }
  }

  // Referral.
  if (labels > 1) {
    char tld[HSK_DNS_MAX_LABEL + 1];

    hsk_dns_label_from(name, -1, tld);

    if (hsk_resource_has(rs, HSK_NS)) {
      hsk_resource_to_ns(rs, tld, ns);
      hsk_resource_to_ds(rs, tld, ns);
      hsk_resource_to_nsip(rs, tld, ar);
      hsk_resource_to_glue(rs, ar, HSK_DNS_NS);
      if (!hsk_resource_has(rs, HSK_DS))
        hsk_dnssec_sign_zsk(ns, HSK_DNS_NS);
      else
        hsk_dnssec_sign_zsk(ns, HSK_DNS_DS);
    } else if (hsk_resource_has(rs, HSK_DELEGATE)) {
      hsk_resource_to_dname(rs, name, an);
      hsk_resource_to_glue(rs, ar, HSK_DNS_DNAME);
      hsk_dnssec_sign_zsk(an, HSK_DNS_DNAME);
      hsk_dnssec_sign_zsk(ar, HSK_DNS_A);
      hsk_dnssec_sign_zsk(ar, HSK_DNS_AAAA);
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

  switch (type) {
    case HSK_DNS_A:
      hsk_resource_to_a(rs, name, an);
      hsk_dnssec_sign_zsk(an, HSK_DNS_A);
      break;
    case HSK_DNS_AAAA:
      hsk_resource_to_aaaa(rs, name, an);
      hsk_dnssec_sign_zsk(an, HSK_DNS_AAAA);
      break;
    case HSK_DNS_CNAME:
      hsk_resource_to_cname(rs, name, an);
      hsk_resource_to_glue(rs, ar, HSK_DNS_CNAME);
      hsk_dnssec_sign_zsk(an, HSK_DNS_CNAME);
      hsk_dnssec_sign_zsk(ar, HSK_DNS_A);
      hsk_dnssec_sign_zsk(ar, HSK_DNS_AAAA);
      break;
    case HSK_DNS_DNAME:
      hsk_resource_to_dname(rs, name, an);
      hsk_resource_to_glue(rs, ar, HSK_DNS_DNAME);
      hsk_dnssec_sign_zsk(an, HSK_DNS_DNAME);
      hsk_dnssec_sign_zsk(ar, HSK_DNS_A);
      hsk_dnssec_sign_zsk(ar, HSK_DNS_AAAA);
      break;
    case HSK_DNS_NS:
      hsk_resource_to_ns(rs, name, ns);
      hsk_resource_to_glue(rs, ar, HSK_DNS_NS);
      hsk_resource_to_nsip(rs, name, ar);
      hsk_dnssec_sign_zsk(ns, HSK_DNS_NS);
      break;
    case HSK_DNS_MX:
      hsk_resource_to_mx(rs, name, an);
      hsk_resource_to_mxip(rs, name, ar);
      hsk_resource_to_glue(rs, ar, HSK_DNS_MX);
      hsk_dnssec_sign_zsk(an, HSK_DNS_MX);
      break;
    case HSK_DNS_TXT:
      hsk_resource_to_txt(rs, name, an);
      hsk_dnssec_sign_zsk(an, HSK_DNS_TXT);
      break;
    case HSK_DNS_LOC:
      hsk_resource_to_loc(rs, name, an);
      hsk_dnssec_sign_zsk(an, HSK_DNS_LOC);
      break;
    case HSK_DNS_DS:
      hsk_resource_to_ds(rs, name, an);
      hsk_dnssec_sign_zsk(an, HSK_DNS_DS);
      break;
    case HSK_DNS_SSHFP:
      hsk_resource_to_sshfp(rs, name, an);
      hsk_dnssec_sign_zsk(an, HSK_DNS_SSHFP);
      break;
    case HSK_DNS_URI:
      hsk_resource_to_uri(rs, name, an);
      hsk_dnssec_sign_zsk(an, HSK_DNS_URI);
      break;
    case HSK_DNS_RP:
      hsk_resource_to_rp(rs, name, an);
      hsk_dnssec_sign_zsk(an, HSK_DNS_RP);
      break;
  }

  if (an->size > 0)
    msg->flags |= HSK_DNS_AA;

  if (an->size == 0 && ns->size == 0) {
    if (hsk_resource_has(rs, HSK_CANONICAL)) {
      msg->flags |= HSK_DNS_AA;
      hsk_resource_to_cname(rs, name, an);
      hsk_resource_to_glue(rs, ar, HSK_DNS_CNAME);
      hsk_dnssec_sign_zsk(an, HSK_DNS_CNAME);
      hsk_dnssec_sign_zsk(ar, HSK_DNS_A);
      hsk_dnssec_sign_zsk(ar, HSK_DNS_AAAA);
    } else if (hsk_resource_has(rs, HSK_NS)) {
      hsk_resource_to_ns(rs, name, ns);
      hsk_resource_to_ds(rs, name, ns);
      hsk_resource_to_nsip(rs, name, ar);
      hsk_resource_to_glue(rs, ar, HSK_DNS_NS);
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

static void
ip_size(const uint8_t *ip, size_t *s, size_t *l) {
  bool out = true;
  int last = 0;
  int i = 0;

  int start = 0;
  int len = 0;

  for (; i < 16; i++) {
    uint8_t ch = ip[i];
    if (out == (ch == 0)) {
      if (!out && i - last > len) {
        start = last;
        len = i - last;
      }
      out = !out;
      last = i;
    }
  }

  if (!out && i - last > len) {
    start = last;
    len = i - last;
  }

  // The worst case:
  // We need at least 2 zeroes in a row to
  // get any benefit from the compression.
  if (len == 16) {
    assert(start == 0);
    len = 0;
  }

  assert(start < 16);
  assert(len < 16);
  assert(start + len <= 16);

  *s = (size_t)start;
  *l = (size_t)len;
}

static size_t
ip_write(const uint8_t *ip, uint8_t *data) {
  size_t start, len;
  ip_size(ip, &start, &len);
  uint8_t left = 16 - (start + len);
  data[0] = (start << 4) | len;
  // Ignore the missing section.
  memcpy(&data[1], ip, start);
  memcpy(&data[1 + start], &ip[start + len], left);
  return 1 + start + left;
}

static bool
ip_read(const uint8_t *data, uint8_t *ip) {
  uint8_t field = data[0];

  uint8_t start = field >> 4;
  uint8_t len = field & 0x0f;

  if (start + len > 16)
    return false;

  uint8_t left = 16 - (start + len);

  // Front half.
  if (ip)
    memcpy(ip, &data[1], start);

  // Fill in the missing section.
  if (ip)
    memset(&ip[start], 0x00, len);

  // Back half.
  if (ip)
    memcpy(&ip[start + len], &data[1 + start], left);

  return true;
}

static void
ip_to_b32(const hsk_target_t *target, char *dst) {
  uint8_t ip[16];

  if (target->type == HSK_INET4) {
    memset(&ip[0], 0x00, 10);
    memset(&ip[10], 0xff, 2);
    memcpy(&ip[12], target->inet4, 4);
  } else {
    memcpy(&ip[0], target->inet6, 16);
  }

  uint8_t data[17];

  size_t size = ip_write(ip, data);
  assert(size <= 17);

  size_t b32_size = hsk_base32_encode_hex_size(data, size, false);
  assert(b32_size <= 29);

  hsk_base32_encode_hex(data, size, dst, false);
}

static bool
b32_to_ip(const char *str, uint8_t *ip, uint16_t *family) {
  size_t size = hsk_base32_decode_hex_size(str);

  if (size == 0 || size > 17)
    return false;

  uint8_t data[17];
  assert(hsk_base32_decode_hex(str, data, false));

  if (!ip_read(data, ip))
    return false;

  if (ip) {
    static const uint8_t mapped[12] = {
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0xff, 0xff
    };

    if (memcmp(ip, (void *)&mapped[0], 12) == 0) {
      memcpy(&ip[0], &ip[12], 4);
      if (family)
        *family = HSK_INET4;
    } else {
      if (family)
        *family = HSK_INET6;
    }
  }

  return true;
}

static bool
pointer_to_ip(const char *name, uint8_t *ip, uint16_t *family) {
  char label[HSK_DNS_MAX_LABEL + 1];
  size_t len = hsk_dns_label_get(name, 0, label);

  if (len < 2 || len > 29 || label[0] != '_')
    return false;

  return b32_to_ip(&label[1], ip, family);
}

static bool
target_to_dns(const hsk_target_t *target, const char *name, char *host) {
  if (target->type == HSK_NAME || target->type == HSK_GLUE) {
    assert(hsk_dns_name_is_fqdn(target->name));
    strcpy(host, target->name);
    return true;
  }

  if (target->type == HSK_INET4 || target->type == HSK_INET6) {
    char b32[29];
    char tld[HSK_DNS_MAX_LABEL + 1];

    ip_to_b32(target, b32);

    int len = hsk_dns_label_get(name, -1, tld);

    if (len <= 0)
      return false;

    sprintf(host, "_%s.%s.", b32, tld);

    return true;
  }

  return false;
}

bool
hsk_resource_is_ptr(const char *name) {
  return pointer_to_ip(name, NULL, NULL);
}
