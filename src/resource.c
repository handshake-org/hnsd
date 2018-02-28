#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <stdbool.h>

#include "ldns/ldns.h"

#include "bio.h"
#include "hsk-addr.h"
#include "hsk-resource.h"
#include "hsk-error.h"
#include "utils.h"
#include "dnssec.h"

static void
ip_size(uint8_t *ip, size_t *s, size_t *l);

static size_t
ip_write(uint8_t *ip, uint8_t *data);

static void
ip_to_b32(hsk_target_t *target, char *dst);

bool
hsk_resource_str_read(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  char **out
) {
  uint8_t size;
  uint8_t *chunk;

  if (!read_u8(data, data_len, &size))
    return false;

  if (!slice_bytes(data, data_len, &chunk, size))
    return false;

  int32_t real_size = 0;
  int32_t i;

  for (i = 0; i < size; i++) {
    uint8_t ch = chunk[i];

    if (ch & 0x80) {
      uint8_t index = ch & 0x7f;
      if (index >= st->size)
        return false;
      real_size += st->sizes[index];
      continue;
    }

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

  if (real_size > 512)
    return false;

  char *str = malloc(real_size + 1);

  if (str == NULL)
    return false;

  char *s = str;
  for (i = 0; i < size; i++) {
    uint8_t ch = chunk[i];

    if (ch & 0x80) {
      uint8_t index = ch & 0x7f;
      assert(index < st->size);

      size_t n = st->sizes[index];
      memcpy(s, st->strings[index], n);

      s += n;

      continue;
    }

    *s = ch;
    s += 1;
  }

  *s ='\0';
  *out = str;

  return true;
}

bool
hsk_resource_target_read(
  uint8_t **data,
  size_t *data_len,
  uint8_t type,
  hsk_symbol_table_t *st,
  hsk_target_t *target
) {
  target->type = type;
  target->name = NULL;

  switch (type) {
    case HSK_INET4: {
      return read_bytes(data, data_len, target->addr, 4);
    }
    case HSK_INET6: {
      uint8_t field;

      if (!read_u8(data, data_len, &field))
        return false;

      uint8_t start = field >> 4;
      uint8_t len = field & 0x0f;
      uint8_t left = 16 - (start + len);

      // Front half.
      if (!read_bytes(data, data_len, target->addr, start))
        return false;

      // Fill in the missing section.
      memset(target->addr + start, 0x00, len);

      // Back half.
      uint8_t *back = target->addr + start + len;

      return read_bytes(data, data_len, back, left);
    }
    case HSK_ONION: {
      return read_bytes(data, data_len, target->addr, 10);
    }
    case HSK_ONIONNG: {
      return read_bytes(data, data_len, target->addr, 33);
    }
    case HSK_NAME: {
      return hsk_resource_str_read(data, data_len, st, &target->name);
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
  hsk_symbol_table_t *st,
  hsk_target_t *target
) {
  uint8_t type;

  if (!read_u8(data, data_len, &type))
    return false;

  return hsk_resource_target_read(data, data_len, type, st, target);
}

bool
hsk_host_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_host_record_t *rec
) {
  return hsk_resource_host_read(data, data_len, st, &rec->target);
}

bool
hsk_txt_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_txt_record_t *rec
) {
  return hsk_resource_str_read(data, data_len, st, &rec->text);
}

bool
hsk_service_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_service_record_t *rec
) {
  if (!hsk_resource_str_read(data, data_len, st, &rec->service))
    goto fail;

  if (!hsk_resource_str_read(data, data_len, st, &rec->protocol))
    goto fail;

  if (!read_u8(data, data_len, &rec->priority))
    goto fail;

  if (!read_u8(data, data_len, &rec->weight))
    goto fail;

  if (!hsk_resource_host_read(data, data_len, st, &rec->target))
    goto fail;

  if (!read_u16(data, data_len, &rec->port))
    goto fail;

  return true;

fail:
  if (rec->service) {
    free(rec->service);
    rec->service = NULL;
  }

  if (rec->protocol) {
    free(rec->protocol);
    rec->protocol = NULL;
  }

  if (rec->target.name) {
    free(rec->target.name);
    rec->target.name = NULL;
  }

  return false;
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
  read_u32(data, data_len, &rec->latitude);
  read_u32(data, data_len, &rec->longitude);
  read_u32(data, data_len, &rec->altitude);

  return true;
}

bool
hsk_magnet_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_magnet_record_t *rec
) {
  if (!hsk_resource_str_read(data, data_len, st, &rec->nid))
    goto fail;

  uint8_t size;
  if (!read_u8(data, data_len, &size))
    goto fail;

  if (!alloc_bytes(data, data_len, &rec->nin, size))
    goto fail;

  rec->nin_len = size;

  return true;

fail:
  if (rec->nid) {
    free(rec->nid);
    rec->nid = NULL;
  }

  if (rec->nin) {
    free(rec->nin);
    rec->nin = NULL;
  }

  return false;
}

bool
hsk_ds_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_ds_record_t *rec
) {
  if (*data_len < 5)
    return false;

  uint8_t size;
  read_u16(data, data_len, &rec->key_tag);
  read_u8(data, data_len, &rec->algorithm);
  read_u8(data, data_len, &rec->digest_type);
  read_u8(data, data_len, &size);

  if (!alloc_bytes(data, data_len, &rec->digest, size))
    return false;

  rec->digest_len = size;

  return true;
}

bool
hsk_tls_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_tls_record_t *rec
) {
  if (!hsk_resource_str_read(data, data_len, st, &rec->protocol))
    goto fail;

  if (*data_len < 6)
    goto fail;

  uint8_t size;
  read_u16(data, data_len, &rec->port);
  read_u8(data, data_len, &rec->usage);
  read_u8(data, data_len, &rec->selector);
  read_u8(data, data_len, &rec->matching_type);
  read_u8(data, data_len, &size);

  if (!alloc_bytes(data, data_len, &rec->certificate, size))
    goto fail;

  rec->certificate_len = size;

  return true;

fail:
  if (rec->protocol) {
    free(rec->protocol);
    rec->protocol = NULL;
  }

  if (rec->certificate) {
    free(rec->certificate);
    rec->certificate = NULL;
  }

  return false;
}

bool
hsk_ssh_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_ssh_record_t *rec
) {
  if (*data_len < 3)
    return false;

  uint8_t size;
  read_u8(data, data_len, &rec->algorithm);
  read_u8(data, data_len, &rec->key_type);
  read_u8(data, data_len, &size);

  if (!alloc_bytes(data, data_len, &rec->fingerprint, size))
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
  return hsk_ssh_record_read(data, data_len, (hsk_ssh_record_t *)rec);
}

bool
hsk_addr_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_addr_record_t *rec
) {
  uint8_t ctype;

  if (!read_u8(data, data_len, &ctype))
    goto fail;

  rec->ctype = ctype;

  switch (ctype) {
    case 0: {
      if (!hsk_resource_str_read(data, data_len, st, &rec->currency))
        goto fail;

      uint8_t size;

      if (!read_u8(data, data_len, &size))
        goto fail;

      if (!alloc_ascii(data, data_len, &rec->address, size))
        goto fail;

      break;
    }
    case 1:
    case 2: { // HSK / BTC
      uint8_t field;

      if (!read_u8(data, data_len, &field))
        goto fail;

      rec->testnet = (field & 0x80) != 0;

      if (!read_u8(data, data_len, &rec->version))
        goto fail;

      uint8_t size = (field & 0x7f) + 1;

      if (!alloc_bytes(data, data_len, &rec->hash, size))
        goto fail;

      rec->hash_len = size;

      if (ctype == 1)
        rec->currency = strdup("hsk");
      else
        rec->currency = strdup("btc");

      if (rec->currency == NULL)
        goto fail;

      break;
    }
    case 3: { // ETH
      rec->currency = strdup("eth");

      if (rec->currency == NULL)
        goto fail;

      if (!alloc_bytes(data, data_len, &rec->hash, 20))
        goto fail;

      rec->hash_len = 20;

      break;
    }
    default: {
      return false;
    }
  }

  return true;

fail:
  if (rec->currency) {
    free(rec->currency);
    rec->currency = NULL;
  }

  if (rec->address) {
    free(rec->address);
    rec->address = NULL;
  }

  if (rec->hash) {
    free(rec->hash);
    rec->hash = NULL;
  }

  return false;
}

bool
hsk_extra_record_read(
  uint8_t **data,
  size_t *data_len,
  hsk_extra_record_t *rec
) {
  uint8_t size;

  if (!read_u8(data, data_len, &size))
    return false;

  if (!alloc_bytes(data, data_len, &rec->data, size))
    return false;

  rec->data_len = size;

  return true;
}

void
hsk_record_init(hsk_record_t *r) {
  if (r == NULL)
    return;

  r->type = r->type;
  r->next = NULL;

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
      memset(rec->target.addr, 0, 33);
      rec->target.name = NULL;
      break;
    }
    case HSK_SERVICE: {
      hsk_service_record_t *rec = (hsk_service_record_t *)r;
      rec->service = NULL;
      rec->protocol = NULL;
      rec->priority = 0;
      rec->weight = 0;
      rec->target.type = 0;
      memset(rec->target.addr, 0, 33);
      rec->target.name = NULL;
      rec->port = 0;
      break;
    }
    case HSK_URL:
    case HSK_EMAIL:
    case HSK_TEXT: {
      hsk_txt_record_t *rec = (hsk_txt_record_t *)r;
      rec->text = NULL;
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
      rec->nid = NULL;
      rec->nin_len = 0;
      rec->nin = NULL;
      break;
    }
    case HSK_DS: {
      hsk_ds_record_t *rec = (hsk_ds_record_t *)r;
      rec->key_tag = 0;
      rec->algorithm = 0;
      rec->digest_type = 0;
      rec->digest_len = 0;
      rec->digest = NULL;
      break;
    }
    case HSK_TLS: {
      hsk_tls_record_t *rec = (hsk_tls_record_t *)r;
      rec->protocol = NULL;
      rec->port = 0;
      rec->usage = 0;
      rec->selector = 0;
      rec->matching_type = 0;
      rec->certificate_len = 0;
      rec->certificate = NULL;
      break;
    }
    case HSK_SSH:
    case HSK_PGP: {
      hsk_ssh_record_t *rec = (hsk_ssh_record_t *)r;
      rec->algorithm = 0;
      rec->key_type = 0;
      rec->fingerprint_len = 0;
      rec->fingerprint = NULL;
      break;
    }
    case HSK_ADDR: {
      hsk_addr_record_t *rec = (hsk_addr_record_t *)r;
      rec->currency = NULL;
      rec->address = NULL;
      rec->ctype = 0;
      rec->testnet = false;
      rec->version = 0;
      rec->hash_len = 0;
      rec->hash = NULL;
      break;
    }
    default: {
      hsk_extra_record_t *rec = (hsk_extra_record_t *)r;
      rec->rtype = 0;
      rec->data_len = 0;
      rec->data = NULL;
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
    case HSK_URL:
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
    case HSK_SSH:
    case HSK_PGP: {
      r = (hsk_record_t *)malloc(sizeof(hsk_ssh_record_t));
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
  r->next = NULL;

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
      if (rec->target.name)
        free(rec->target.name);
      free(rec);
      break;
    }
    case HSK_SERVICE: {
      hsk_service_record_t *rec = (hsk_service_record_t *)r;
      if (rec->service)
        free(rec->service);
      if (rec->protocol)
        free(rec->protocol);
      if (rec->target.name)
        free(rec->target.name);
      free(rec);
      break;
    }
    case HSK_URL:
    case HSK_EMAIL:
    case HSK_TEXT: {
      hsk_txt_record_t *rec = (hsk_txt_record_t *)r;
      if (rec->text)
        free(rec->text);
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
      if (rec->nid)
        free(rec->nid);
      if (rec->nin)
        free(rec->nin);
      free(rec);
      break;
    }
    case HSK_DS: {
      hsk_ds_record_t *rec = (hsk_ds_record_t *)r;
      if (rec->digest)
        free(rec->digest);
      free(rec);
      break;
    }
    case HSK_TLS: {
      hsk_tls_record_t *rec = (hsk_tls_record_t *)r;
      if (rec->protocol)
        free(rec->protocol);
      if (rec->certificate)
        free(rec->certificate);
      free(rec);
      break;
    }
    case HSK_SSH:
    case HSK_PGP: {
      hsk_ssh_record_t *rec = (hsk_ssh_record_t *)r;
      if (rec->fingerprint)
        free(rec->fingerprint);
      free(rec);
      break;
    }
    case HSK_ADDR: {
      hsk_addr_record_t *rec = (hsk_addr_record_t *)r;
      if (rec->currency)
        free(rec->currency);
      if (rec->address)
        free(rec->address);
      free(rec);
      break;
    }
    default: {
      hsk_extra_record_t *rec = (hsk_extra_record_t *)r;
      if (rec->data)
        free(rec->data);
      free(rec);
      break;
    }
  }
}

void
hsk_record_free_list(hsk_record_t *records) {
  hsk_record_t *r, *n;
  for (r = records; r; r = n) {
    n = r->next;
    hsk_record_free(r);
  }
}

void
hsk_resource_free(hsk_resource_t *res) {
  if (res == NULL)
    return;
  hsk_record_free_list(res->records);
  free(res);
}

bool
hsk_record_read(
  uint8_t **data,
  size_t *data_len,
  uint8_t type,
  hsk_symbol_table_t *st,
  hsk_record_t **r
) {
  *r = hsk_record_alloc(type);

  if (*r == NULL)
    return false;

  bool result = true;

  switch (type) {
    case HSK_INET4:
    case HSK_INET6:
    case HSK_ONION:
    case HSK_ONIONNG:
    case HSK_NAME: {
      hsk_host_record_t *rec = (hsk_host_record_t *)*r;
      result = hsk_resource_target_read(data, data_len, type, st, &rec->target);
      break;
    }
    case HSK_CANONICAL:
    case HSK_DELEGATE:
    case HSK_NS: {
      hsk_host_record_t *rec = (hsk_host_record_t *)*r;
      result = hsk_host_record_read(data, data_len, st, rec);
      break;
    }
    case HSK_SERVICE: {
      hsk_service_record_t *rec = (hsk_service_record_t *)*r;
      result = hsk_service_record_read(data, data_len, st, rec);
      break;
    }
    case HSK_URL:
    case HSK_EMAIL:
    case HSK_TEXT: {
      hsk_txt_record_t *rec = (hsk_txt_record_t *)*r;
      result = hsk_txt_record_read(data, data_len, st, rec);
      break;
    }
    case HSK_LOCATION: {
      hsk_location_record_t *rec = (hsk_location_record_t *)*r;
      result = hsk_location_record_read(data, data_len, rec);
      break;
    }
    case HSK_MAGNET: {
      hsk_magnet_record_t *rec = (hsk_magnet_record_t *)*r;
      result = hsk_magnet_record_read(data, data_len, st, rec);
      break;
    }
    case HSK_DS: {
      hsk_ds_record_t *rec = (hsk_ds_record_t *)*r;
      result = hsk_ds_record_read(data, data_len, rec);
      break;
    }
    case HSK_TLS: {
      hsk_tls_record_t *rec = (hsk_tls_record_t *)*r;
      result = hsk_tls_record_read(data, data_len, st, rec);
      break;
    }
    case HSK_SSH:
    case HSK_PGP: {
      hsk_ssh_record_t *rec = (hsk_ssh_record_t *)*r;
      result = hsk_ssh_record_read(data, data_len, rec);
      break;
    }
    case HSK_ADDR: {
      hsk_addr_record_t *rec = (hsk_addr_record_t *)*r;
      result = hsk_addr_record_read(data, data_len, st, rec);
      break;
    }
    default: {
      hsk_extra_record_t *rec = (hsk_extra_record_t *)*r;
      result = hsk_extra_record_read(data, data_len, rec);
      break;
    }
  }

  if (!result) {
    free(*r);
    return false;
  }

  return true;
}

bool
hsk_resource_decode(
  uint8_t *data,
  size_t data_len,
  hsk_resource_t **resource
) {
  bool result = true;

  hsk_symbol_table_t st;
  st.size = 0;

  hsk_resource_t *res = malloc(sizeof(hsk_resource_t));

  if (res == NULL)
    goto fail;

  res->version = 0;
  res->ttl = 0;
  res->records = NULL;

  if (!read_u8(&data, &data_len, &res->version))
    goto fail;

  if (res->version != 0)
    goto fail;

  uint16_t field;
  if (!read_u16(&data, &data_len, &field))
    goto fail;

  res->ttl = ((uint32_t)field) << 6;

  uint8_t st_size;
  if (!read_u8(&data, &data_len, &st_size))
    goto fail;

  int32_t i;
  for (i = 0; i < st_size; i++) {
    uint8_t size;

    if (!read_u8(&data, &data_len, &size))
      goto fail;

    if (!slice_ascii(&data, &data_len, &st.strings[i], size))
      goto fail;

    st.sizes[i] = size;
    st.size += 1;
  }

  hsk_record_t *parent = NULL;

  while (data_len > 0) {
    hsk_record_t *record;
    uint8_t type;

    read_u8(&data, &data_len, &type);

    if (!hsk_record_read(&data, &data_len, type, &st, &record))
      goto fail;

    if (res->records == NULL)
      res->records = record;

    if (parent)
      parent->next = record;

    parent = record;
  }

  *resource = res;

  goto done;

fail:
  hsk_resource_free(res);
  result = false;

done:
  return result;
}

hsk_record_t *
hsk_resource_get(hsk_resource_t *res, uint8_t type) {
  hsk_record_t *c, *n;
  for (c = res->records; c; c = c->next) {
    if (c->type == type)
      return c;
  }
  return NULL;
}

bool
hsk_resource_has(hsk_resource_t *res, uint8_t type) {
  return hsk_resource_get(res, type) != NULL;
}

void
hsk_resource_to_a(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_INET4)
      continue;

    hsk_inet4_record_t *rec = (hsk_inet4_record_t *)c;
    hsk_target_t *target = &rec->target;

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, LDNS_RR_TYPE_A);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(name));

    ldns_rr_push_rdf(rr,
      ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NONE, 4, target->addr));

    ldns_rr_list_push_rr(an, rr);
  }
}

void
hsk_resource_to_aaaa(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_INET6)
      continue;

    hsk_inet6_record_t *rec = (hsk_inet6_record_t *)c;
    hsk_target_t *target = &rec->target;

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, LDNS_RR_TYPE_AAAA);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(name));

    ldns_rr_push_rdf(rr,
      ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NONE, 16, target->addr));

    ldns_rr_list_push_rr(an, rr);
  }
}

void
hsk_resource_to_cname(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_CANONICAL)
      continue;

    hsk_canonical_record_t *rec = (hsk_canonical_record_t *)c;
    hsk_target_t *target = &rec->target;

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, LDNS_RR_TYPE_CNAME);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(name));

    if (strlen(target->name) > 253)
      continue;

    char targ[256];
    sprintf(targ, "%s.", target->name);

    ldns_rr_push_rdf(rr, ldns_dname_new_frm_str(targ));

    ldns_rr_list_push_rr(an, rr);
  }
}

void
hsk_resource_to_dname(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_DELEGATE)
      continue;

    hsk_delegate_record_t *rec = (hsk_delegate_record_t *)c;
    hsk_target_t *target = &rec->target;

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, LDNS_RR_TYPE_DNAME);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(name));

    if (strlen(target->name) > 253)
      continue;

    char targ[256];
    sprintf(targ, "%s.", target->name);

    ldns_rr_push_rdf(rr, ldns_dname_new_frm_str(targ));

    ldns_rr_list_push_rr(an, rr);
  }
}

void
hsk_resource_to_ns(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_NS)
      continue;

    hsk_ns_record_t *rec = (hsk_ns_record_t *)c;
    hsk_target_t *target = &rec->target;

    char nsname[286];

    if (target->type == HSK_NAME) {
      if (strlen(target->name) > 253)
        continue;
      sprintf(nsname, "%s.", target->name);
    } else if (target->type == HSK_INET4 || target->type == HSK_INET6) {
      char b32[29];
      ip_to_b32(target, b32);
      sprintf(nsname, "_%s.%s", b32, name);
    } else {
      continue;
    }

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, LDNS_RR_TYPE_NS);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(name));

    ldns_rr_push_rdf(rr, ldns_dname_new_frm_str(nsname));

    ldns_rr_list_push_rr(an, rr);
  }
}

void
hsk_resource_to_nsip(hsk_resource_t *res, char *name, ldns_rr_list *ad) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_NS)
      continue;

    hsk_ns_record_t *rec = (hsk_ns_record_t *)c;
    hsk_target_t *target = &rec->target;

    if (target->type != HSK_INET4 && target->type != HSK_INET6)
      continue;

    char ptr[286];

    ldns_rr_type rrtype = target->type == HSK_INET4
      ? LDNS_RR_TYPE_A
      : LDNS_RR_TYPE_AAAA;

    ldns_rdf_type rdftype = target->type == HSK_INET4
      ? LDNS_RDF_TYPE_A
      : LDNS_RDF_TYPE_AAAA;

    size_t size = target->type == HSK_INET4 ? 4 : 16;

    char b32[29];
    ip_to_b32(target, b32);
    sprintf(ptr, "_%s.%s", b32, name);

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, rrtype);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(ptr));

    ldns_rr_push_rdf(rr, ldns_rdf_new_frm_data(rdftype, size, target->addr));

    ldns_rr_list_push_rr(ad, rr);
  }
}

static void
hsk__resource_to_srvip(
  hsk_resource_t *res,
  char *name,
  ldns_rr_list *ad,
  bool mx
) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_SERVICE)
      continue;

    hsk_service_record_t *rec = (hsk_service_record_t *)c;
    hsk_target_t *target = &rec->target;

    if (target->type != HSK_INET4 && target->type != HSK_INET6)
      continue;

    if (mx) {
      if (strcmp(rec->service, "smtp") != 0
          || strcmp(rec->protocol, "tcp") != 0) {
        continue;
      }
    }

    char ptr[286];

    ldns_rr_type rrtype = target->type == HSK_INET4
      ? LDNS_RR_TYPE_A
      : LDNS_RR_TYPE_AAAA;

    ldns_rdf_type rdftype = target->type == HSK_INET4
      ? LDNS_RDF_TYPE_A
      : LDNS_RDF_TYPE_AAAA;

    size_t size = target->type == HSK_INET4 ? 4 : 16;

    char b32[29];
    ip_to_b32(target, b32);
    sprintf(ptr, "_%s.%s", b32, name);

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, rrtype);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(ptr));

    ldns_rr_push_rdf(rr, ldns_rdf_new_frm_data(rdftype, size, target->addr));

    ldns_rr_list_push_rr(ad, rr);
  }
}

void
hsk_resource_to_mx(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_SERVICE)
      continue;

    hsk_service_record_t *rec = (hsk_service_record_t *)c;
    hsk_target_t *target = &rec->target;

    if (strcmp(rec->service, "smtp") != 0
        || strcmp(rec->protocol, "tcp") != 0) {
      continue;
    }

    char targ[286];

    if (target->type == HSK_NAME) {
      if (strlen(target->name) > 253)
        continue;
      sprintf(targ, "%s.", target->name);
    } else if (target->type == HSK_INET4 || target->type == HSK_INET6) {
      char b32[29];
      ip_to_b32(target, b32);
      sprintf(targ, "_%s.%s", b32, name);
    } else {
      continue;
    }

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, LDNS_RR_TYPE_MX);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(name));

    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, rec->priority));
    ldns_rr_push_rdf(rr, ldns_dname_new_frm_str(targ));

    ldns_rr_list_push_rr(an, rr);
  }
}

void
hsk_resource_to_mxip(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  return hsk__resource_to_srvip(res, name, an, true);
}

void
hsk_resource_to_srv(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_SERVICE)
      continue;

    hsk_service_record_t *rec = (hsk_service_record_t *)c;
    hsk_target_t *target = &rec->target;

    char targ[286];

    if (target->type == HSK_NAME) {
      if (strlen(target->name) > 253)
        continue;
      sprintf(targ, "%s.", target->name);
    } else if (target->type == HSK_INET4 || target->type == HSK_INET6) {
      char b32[29];
      ip_to_b32(target, b32);
      sprintf(targ, "_%s.%s", b32, name);
    } else {
      continue;
    }

    if (strlen(rec->service) + strlen(rec->protocol) + strlen(name) + 4 > 253)
      continue;

    char rname[256];
    sprintf(rname, "_%s._%s.%s", rec->service, rec->protocol, name);

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, LDNS_RR_TYPE_SRV);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(rname));

    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, rec->priority));
    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, rec->weight));
    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, rec->port));
    ldns_rr_push_rdf(rr, ldns_dname_new_frm_str(targ));

    ldns_rr_list_push_rr(an, rr);
  }
}

void
hsk_resource_to_srvip(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  return hsk__resource_to_srvip(res, name, an, false);
}

void
hsk_resource_to_txt(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  hsk_record_t *c, *n;

  ldns_rr *rr = ldns_rr_new();
  ldns_rr_set_ttl(rr, res->ttl);
  ldns_rr_set_type(rr, LDNS_RR_TYPE_TXT);
  ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
  ldns_rr_set_owner(rr, ldns_dname_new_frm_str(name));

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_TEXT)
      continue;

    hsk_text_record_t *rec = (hsk_text_record_t *)c;

    ldns_rr_push_rdf(rr, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_STR, rec->text));
  }

  ldns_rr_list_push_rr(an, rr);
}

void
hsk_resource_to_loc(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_LOCATION)
      continue;

    hsk_location_record_t *rec = (hsk_location_record_t *)c;

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, LDNS_RR_TYPE_LOC);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(name));

    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, rec->version));
    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, rec->size));
    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, rec->horiz_pre));
    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, rec->vert_pre));
    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, rec->latitude));
    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, rec->longitude));
    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, rec->altitude));

    ldns_rr_list_push_rr(an, rr);
  }
}

void
hsk_resource_to_ds(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_DS)
      continue;

    hsk_ds_record_t *rec = (hsk_ds_record_t *)c;

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, LDNS_RR_TYPE_DS);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(name));

    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, rec->key_tag));
    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, rec->algorithm));
    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, rec->digest_type));
    ldns_rr_push_rdf(rr,
      ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NONE, rec->digest_len, rec->digest));

    ldns_rr_list_push_rr(an, rr);
  }
}

void
hsk_resource_to_tlsa(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_TLS)
      continue;

    hsk_tls_record_t *rec = (hsk_tls_record_t *)c;

    if (5 + strlen(rec->protocol) + strlen(name) + 4 > 253)
      continue;

    char rname[256];
    sprintf(rname, "_%d._%s.%s", rec->port, rec->protocol, name);

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, LDNS_RR_TYPE_TLSA);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(rname));

    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, rec->usage));
    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, rec->selector));
    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, rec->matching_type));
    ldns_rr_push_rdf(rr,
      ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NONE,
        rec->certificate_len, rec->certificate));

    ldns_rr_list_push_rr(an, rr);
  }
}

void
hsk_resource_to_sshfp(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_SSH)
      continue;

    hsk_ssh_record_t *rec = (hsk_ssh_record_t *)c;

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, LDNS_RR_TYPE_SSHFP);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(name));

    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, rec->algorithm));
    ldns_rr_push_rdf(rr,
      ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, rec->key_type));
    ldns_rr_push_rdf(rr,
      ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NONE,
        rec->fingerprint_len, rec->fingerprint));

    ldns_rr_list_push_rr(an, rr);
  }
}

void
hsk_resource_to_openpgpkey(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_PGP)
      continue;

    hsk_pgp_record_t *rec = (hsk_pgp_record_t *)c;

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, LDNS_RR_TYPE_OPENPGPKEY);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(name));

    ldns_rr_list_push_rr(an, rr);
  }
}

void
hsk_resource_to_uri(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_URL)
      continue;

    hsk_url_record_t *rec = (hsk_url_record_t *)c;

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, LDNS_RR_TYPE_URI);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(name));

    ldns_rr_push_rdf(rr, ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, 0));
    ldns_rr_push_rdf(rr, ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, 0));
    ldns_rr_push_rdf(rr, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_STR, rec->text));

    ldns_rr_list_push_rr(an, rr);
  }
}

void
hsk_resource_to_rp(hsk_resource_t *res, char *name, ldns_rr_list *an) {
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type != HSK_EMAIL)
      continue;

    hsk_email_record_t *rec = (hsk_email_record_t *)c;

    ldns_rr *rr = ldns_rr_new();
    ldns_rr_set_ttl(rr, res->ttl);
    ldns_rr_set_type(rr, LDNS_RR_TYPE_RP);
    ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_owner(rr, ldns_dname_new_frm_str(name));

    ldns_rr_push_rdf(rr, ldns_dname_new_frm_str(rec->text));
    ldns_rr_push_rdf(rr, ldns_dname_new_frm_str("."));

    ldns_rr_list_push_rr(an, rr);
  }
}

bool
hsk_resource_to_dns(
  hsk_resource_t *rs,
  uint16_t id,
  char *fqdn,
  uint16_t type,
  bool edns,
  bool dnssec,
  uint8_t **wire,
  size_t *wire_len
) {
  ldns_rdf *rdf = ldns_dname_new_frm_str(fqdn);

  if (!rdf)
    return false;

  size_t labels = ldns_dname_label_count(rdf);

  ldns_rdf *tld_rdf = ldns_dname_label(rdf, labels - 1);

  if (!tld_rdf) {
    ldns_rdf_deep_free(rdf);
    return false;
  }

  char *name = ldns_rdf2str(tld_rdf);

  if (!name) {
    ldns_rdf_deep_free(rdf);
    ldns_rdf_deep_free(tld_rdf);
    return false;
  }

  ldns_pkt *res = ldns_pkt_new();
  ldns_rr_list *qd = ldns_rr_list_new();
  ldns_rr_list *an = ldns_rr_list_new();
  ldns_rr_list *ns = ldns_rr_list_new();
  ldns_rr_list *ad = ldns_rr_list_new();
  ldns_rr *qs = ldns_rr_new();

  if (!res || !qd || !an || !ns || !ad || !qs) {
    ldns_rdf_deep_free(rdf);
    ldns_rdf_deep_free(tld_rdf);

    free(name);

    if (res)
      ldns_pkt_free(res);

    if (qd)
      ldns_rr_list_free(qd);

    if (an)
      ldns_rr_list_free(an);

    if (ns)
      ldns_rr_list_free(ns);

    if (ad)
      ldns_rr_list_free(ad);

    return false;
  }

  ldns_pkt_set_id(res, id);
  ldns_pkt_set_qr(res, 1);

  if (edns) {
    ldns_pkt_set_edns_udp_size(res, 4096);
    if (dnssec) {
      ldns_pkt_set_edns_do(res, 1);
      ldns_pkt_set_ad(res, 1);
    }
  }

  ldns_rr_set_question(qs, 1);
  ldns_rr_set_type(qs, (ldns_rr_type)type);
  ldns_rr_set_class(qs, LDNS_RR_CLASS_IN);
  ldns_rr_set_owner(qs, rdf);

  ldns_rr_list_push_rr(qd, qs);

  if (labels > 1) {
    if (hsk_resource_has(rs, HSK_NS)) {
      hsk_resource_to_ns(rs, name, ns);
      hsk_dnssec_sign(ns, LDNS_RR_TYPE_NS, dnssec);
      hsk_resource_to_nsip(rs, name, ad);
      if (dnssec)
        hsk_resource_to_ds(rs, name, ns);
      hsk_dnssec_sign(ns, LDNS_RR_TYPE_DS, dnssec);
    } else if (hsk_resource_has(rs, HSK_DELEGATE)) {
      hsk_resource_to_dname(rs, name, an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_DNAME, dnssec);
    }

    goto done;
  }

  switch ((ldns_rr_type)type) {
    case LDNS_RR_TYPE_A:
      hsk_resource_to_a(rs, name, an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_A, dnssec);
      break;
    case LDNS_RR_TYPE_AAAA:
      hsk_resource_to_aaaa(rs, name, an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_AAAA, dnssec);
      break;
    case LDNS_RR_TYPE_CNAME:
      hsk_resource_to_cname(rs, name, an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_CNAME, dnssec);
      break;
    case LDNS_RR_TYPE_DNAME:
      hsk_resource_to_dname(rs, name, an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_DNAME, dnssec);
      break;
    case LDNS_RR_TYPE_NS:
      hsk_resource_to_ns(rs, name, ns);
      hsk_resource_to_nsip(rs, name, ad);
      hsk_dnssec_sign(ns, LDNS_RR_TYPE_NS, dnssec);
      break;
    case LDNS_RR_TYPE_MX:
      hsk_resource_to_mx(rs, name, an);
      hsk_resource_to_mxip(rs, name, ad);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_MX, dnssec);
      break;
    case LDNS_RR_TYPE_SRV:
      hsk_resource_to_srv(rs, name, an);
      hsk_resource_to_srvip(rs, name, ad);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_SRV, dnssec);
      break;
    case LDNS_RR_TYPE_TXT:
      hsk_resource_to_txt(rs, name, an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_TXT, dnssec);
      break;
    case LDNS_RR_TYPE_LOC:
      hsk_resource_to_loc(rs, name, an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_LOC, dnssec);
      break;
    case LDNS_RR_TYPE_DS:
      hsk_resource_to_ds(rs, name, an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_DS, dnssec);
      break;
    case LDNS_RR_TYPE_TLSA:
      hsk_resource_to_tlsa(rs, name, an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_TLSA, dnssec);
      break;
    case LDNS_RR_TYPE_SSHFP:
      hsk_resource_to_sshfp(rs, name, an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_SSHFP, dnssec);
      break;
    case LDNS_RR_TYPE_OPENPGPKEY:
      hsk_resource_to_openpgpkey(rs, name, an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_OPENPGPKEY, dnssec);
      break;
    case LDNS_RR_TYPE_URI:
      hsk_resource_to_uri(rs, name, an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_URI, dnssec);
      break;
    case LDNS_RR_TYPE_RP:
      hsk_resource_to_rp(rs, name, an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_RP, dnssec);
      break;
  }

  if (ldns_rr_list_rr_count(an) > 0)
    ldns_pkt_set_aa(res, 1);

  if (ldns_rr_list_rr_count(an) == 0
      && ldns_rr_list_rr_count(ns) == 0) {
    if (hsk_resource_has(rs, HSK_CANONICAL)) {
      ldns_pkt_set_aa(res, 1);
      hsk_resource_to_cname(rs, name, an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_CNAME, dnssec);
      goto done;
    }

    if (hsk_resource_has(rs, HSK_NS)) {
      hsk_resource_to_ns(rs, name, ns);
      hsk_dnssec_sign(ns, LDNS_RR_TYPE_NS, dnssec);
      hsk_resource_to_nsip(rs, name, ad);
      if (dnssec)
        hsk_resource_to_ds(rs, name, ns);
      hsk_dnssec_sign(ns, LDNS_RR_TYPE_DS, dnssec);
    }
  }

done:
  ldns_rdf_deep_free(tld_rdf);

  free(name);

  ldns_pkt_push_rr_list(res, LDNS_SECTION_QUESTION, qd);
  ldns_pkt_push_rr_list(res, LDNS_SECTION_ANSWER, an);
  ldns_pkt_push_rr_list(res, LDNS_SECTION_AUTHORITY, ns);
  ldns_pkt_push_rr_list(res, LDNS_SECTION_ADDITIONAL, ad);

  ldns_status rc = ldns_pkt2wire(wire, res, wire_len);

  ldns_pkt_free(res);
  ldns_rr_list_free(qd);
  ldns_rr_list_free(an);
  ldns_rr_list_free(ns);
  ldns_rr_list_free(ad);

  return rc == LDNS_STATUS_OK;
}

void
hsk_resource_root_to_soa(ldns_rr_list *an) {
  ldns_rr *rr = ldns_rr_new();
  ldns_rr_set_ttl(rr, 86400);
  ldns_rr_set_type(rr, LDNS_RR_TYPE_SOA);
  ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
  ldns_rr_set_owner(rr, ldns_dname_new_frm_str("."));

  ldns_rr_push_rdf(rr, ldns_dname_new_frm_str(".")); // ns
  ldns_rr_push_rdf(rr, ldns_dname_new_frm_str(".")); // mbox
  ldns_rr_push_rdf(rr,
    ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, (uint32_t)hsk_now())); // serial
  ldns_rr_push_rdf(rr,
    ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, 1800)); // refresh
  ldns_rr_push_rdf(rr,
    ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, 900)); // retry
  ldns_rr_push_rdf(rr,
    ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, 604800)); // expire
  ldns_rr_push_rdf(rr,
    ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, 86400)); // minttl

  ldns_rr_list_push_rr(an, rr);
}

void
hsk_resource_root_to_ns(ldns_rr_list *an) {
  ldns_rr *rr = ldns_rr_new();
  ldns_rr_set_ttl(rr, 518400);
  ldns_rr_set_type(rr, LDNS_RR_TYPE_NS);
  ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
  ldns_rr_set_owner(rr, ldns_dname_new_frm_str("."));

  ldns_rr_push_rdf(rr, ldns_dname_new_frm_str("."));

  ldns_rr_list_push_rr(an, rr);
}

void
hsk_resource_root_to_a(ldns_rr_list *an, hsk_addr_t *addr) {
  if (!addr || !hsk_addr_is_ip4(addr))
    return;

  uint8_t *ip = hsk_addr_get_ip(addr);

  ldns_rr *rr = ldns_rr_new();
  ldns_rr_set_ttl(rr, 518400);
  ldns_rr_set_type(rr, LDNS_RR_TYPE_A);
  ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
  ldns_rr_set_owner(rr, ldns_dname_new_frm_str("."));

  ldns_rr_push_rdf(rr,
    ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NONE, 4, (uint8_t *)ip));

  ldns_rr_list_push_rr(an, rr);
}

void
hsk_resource_root_to_aaaa(ldns_rr_list *an, hsk_addr_t *addr) {
  if (!addr || !hsk_addr_is_ip6(addr))
    return;

  uint8_t *ip = hsk_addr_get_ip(addr);

  ldns_rr *rr = ldns_rr_new();
  ldns_rr_set_ttl(rr, 518400);
  ldns_rr_set_type(rr, LDNS_RR_TYPE_AAAA);
  ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
  ldns_rr_set_owner(rr, ldns_dname_new_frm_str("."));

  ldns_rr_push_rdf(rr,
    ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NONE, 16, (uint8_t *)ip));

  ldns_rr_list_push_rr(an, rr);
}

void
hsk_resource_root_to_dnskey(ldns_rr_list *an) {
  ldns_rr_list_push_rr(an, hsk_dnssec_get_dnskey());
}

void
hsk_resource_root_to_ds(ldns_rr_list *an) {
  ldns_rr_list_push_rr(an, hsk_dnssec_get_ds());
}

bool
hsk_resource_root(
  uint16_t id,
  uint16_t type,
  bool edns,
  bool dnssec,
  hsk_addr_t *addr,
  uint8_t **wire,
  size_t *wire_len
) {
  ldns_rdf *rdf = ldns_dname_new_frm_str(".");

  if (!rdf)
    return false;

  ldns_pkt *res = ldns_pkt_new();
  ldns_rr_list *qd = ldns_rr_list_new();
  ldns_rr_list *an = ldns_rr_list_new();
  ldns_rr_list *ns = ldns_rr_list_new();
  ldns_rr_list *ad = ldns_rr_list_new();
  ldns_rr *qs = ldns_rr_new();

  if (!res || !qd || !an || !ns || !ad || !qs) {
    ldns_rdf_deep_free(rdf);

    if (res)
      ldns_pkt_free(res);

    if (qd)
      ldns_rr_list_free(qd);

    if (an)
      ldns_rr_list_free(an);

    if (ns)
      ldns_rr_list_free(ns);

    if (ad)
      ldns_rr_list_free(ad);

    return false;
  }

  ldns_pkt_set_id(res, id);
  ldns_pkt_set_qr(res, 1);
  ldns_pkt_set_aa(res, 1);

  if (edns) {
    ldns_pkt_set_edns_udp_size(res, 4096);
    if (dnssec) {
      ldns_pkt_set_edns_do(res, 1);
      ldns_pkt_set_ad(res, 1);
    }
  }

  ldns_rr_set_question(qs, 1);
  ldns_rr_set_type(qs, (ldns_rr_type)type);
  ldns_rr_set_class(qs, LDNS_RR_CLASS_IN);
  ldns_rr_set_owner(qs, rdf);

  ldns_rr_list_push_rr(qd, qs);

  switch ((ldns_rr_type)type) {
    case LDNS_RR_TYPE_ANY:
    case LDNS_RR_TYPE_NS:
      hsk_resource_root_to_ns(an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_NS, dnssec);
      if (hsk_addr_is_ip4(addr)) {
        hsk_resource_root_to_a(ad, addr);
        hsk_dnssec_sign(ad, LDNS_RR_TYPE_A, dnssec);
      }
      if (hsk_addr_is_ip6(addr)) {
        hsk_resource_root_to_aaaa(ad, addr);
        hsk_dnssec_sign(ad, LDNS_RR_TYPE_AAAA, dnssec);
      }
      break;
    case LDNS_RR_TYPE_SOA:
      hsk_resource_root_to_soa(an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_SOA, dnssec);
      hsk_resource_root_to_ns(ns);
      hsk_dnssec_sign(ns, LDNS_RR_TYPE_NS, dnssec);
      if (hsk_addr_is_ip4(addr)) {
        hsk_resource_root_to_a(ad, addr);
        hsk_dnssec_sign(ad, LDNS_RR_TYPE_A, dnssec);
      }
      if (hsk_addr_is_ip6(addr)) {
        hsk_resource_root_to_aaaa(ad, addr);
        hsk_dnssec_sign(ad, LDNS_RR_TYPE_AAAA, dnssec);
      }
      break;
    case LDNS_RR_TYPE_DNSKEY:
      hsk_resource_root_to_dnskey(an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_DNSKEY, dnssec);
      break;
    case LDNS_RR_TYPE_DS:
      hsk_resource_root_to_ds(an);
      hsk_dnssec_sign(an, LDNS_RR_TYPE_DS, dnssec);
      break;
  }

  if (ldns_rr_list_rr_count(an) == 0
      && ldns_rr_list_rr_count(ns) == 0) {
    hsk_resource_root_to_soa(ns);
    hsk_dnssec_sign(ns, LDNS_RR_TYPE_SOA, dnssec);
  }

  ldns_pkt_push_rr_list(res, LDNS_SECTION_QUESTION, qd);
  ldns_pkt_push_rr_list(res, LDNS_SECTION_ANSWER, an);
  ldns_pkt_push_rr_list(res, LDNS_SECTION_AUTHORITY, ns);
  ldns_pkt_push_rr_list(res, LDNS_SECTION_ADDITIONAL, ad);

  ldns_status rc = ldns_pkt2wire(wire, res, wire_len);

  ldns_pkt_free(res);
  ldns_rr_list_free(qd);
  ldns_rr_list_free(an);
  ldns_rr_list_free(ns);
  ldns_rr_list_free(ad);

  return rc == LDNS_STATUS_OK;
}

bool
hsk_resource_to_nx(
  uint16_t id,
  char *fqdn,
  uint16_t type,
  bool edns,
  bool dnssec,
  uint8_t **wire,
  size_t *wire_len
) {
  ldns_rdf *rdf = ldns_dname_new_frm_str(fqdn);

  if (!rdf)
    return false;

  ldns_pkt *res = ldns_pkt_new();
  ldns_rr_list *qd = ldns_rr_list_new();
  ldns_rr_list *an = ldns_rr_list_new();
  ldns_rr_list *ns = ldns_rr_list_new();
  ldns_rr_list *ad = ldns_rr_list_new();
  ldns_rr *qs = ldns_rr_new();

  if (!res || !qd || !an || !ns || !ad || !qs) {
    ldns_rdf_deep_free(rdf);

    if (res)
      ldns_pkt_free(res);

    if (qd)
      ldns_rr_list_free(qd);

    if (an)
      ldns_rr_list_free(an);

    if (ns)
      ldns_rr_list_free(ns);

    if (ad)
      ldns_rr_list_free(ad);

    return false;
  }

  ldns_pkt_set_id(res, id);
  ldns_pkt_set_rcode(res, LDNS_RCODE_NXDOMAIN);
  ldns_pkt_set_qr(res, 1);
  ldns_pkt_set_aa(res, 1);

  if (edns) {
    ldns_pkt_set_edns_udp_size(res, 4096);
    if (dnssec) {
      ldns_pkt_set_edns_do(res, 1);
      ldns_pkt_set_ad(res, 1);
    }
  }

  ldns_rr_set_question(qs, 1);
  ldns_rr_set_type(qs, (ldns_rr_type)type);
  ldns_rr_set_class(qs, LDNS_RR_CLASS_IN);
  ldns_rr_set_owner(qs, rdf);

  ldns_rr_list_push_rr(qd, qs);

  hsk_resource_root_to_soa(ns);
  // We should also be giving an NSEC proof
  // here, but I don't think it's possible
  // with the current construction.
  hsk_dnssec_sign(ns, LDNS_RR_TYPE_SOA, dnssec);

  ldns_pkt_push_rr_list(res, LDNS_SECTION_QUESTION, qd);
  ldns_pkt_push_rr_list(res, LDNS_SECTION_ANSWER, an);
  ldns_pkt_push_rr_list(res, LDNS_SECTION_AUTHORITY, ns);
  ldns_pkt_push_rr_list(res, LDNS_SECTION_ADDITIONAL, ad);

  ldns_status rc = ldns_pkt2wire(wire, res, wire_len);

  ldns_pkt_free(res);
  ldns_rr_list_free(qd);
  ldns_rr_list_free(an);
  ldns_rr_list_free(ns);
  ldns_rr_list_free(ad);

  return rc == LDNS_STATUS_OK;
}

/*
 * Helpers
 */

static void
ip_size(uint8_t *ip, size_t *s, size_t *l) {
  bool out = true;
  int32_t last = 0;
  int32_t i = 0;

  int32_t start = 0;
  int32_t len = 0;

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

  *s = (size_t)start;
  *l = (size_t)len;
}

static size_t
ip_write(uint8_t *ip, uint8_t *data) {
  size_t start, len;
  ip_size(ip, &start, &len);
  data[0] = (start << 4) | len;
  // Ignore the missing section.
  memcpy(data + 1, ip, start);
  memcpy(data + 1 + start, ip + start + len, 16 - (start + len));
  return 1 + start + (16 - (start + len));
}

static void
ip_to_b32(hsk_target_t *target, char *dst) {
  uint8_t ip[16];

  if (target->type == HSK_INET4) {
    memset(ip + 0, 0x00, 10);
    memset(ip + 10, 0xff, 2);
    memcpy(ip + 12, target->addr, 4);
  } else {
    memcpy(ip, target->addr, 16);
  }

  uint8_t data[17];
  size_t size = ip_write(ip, data);

  char b32[65];

  ldns_b32_ntop_extended_hex(target->addr, size, b32, 65);

  int32_t i;
  for (i = 0; i < 64; i++) {
    if (b32[i] == '=' || b32[i] == '\0')
      break;
  }

  b32[i] = '\0';

  strcpy(dst, b32);
}
