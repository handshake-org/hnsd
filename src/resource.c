#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <stdbool.h>

#include "bio.h"
#include "hsk-resource.h"
#include "hsk-error.h"

bool
hsk_read_compressed(
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

  char *str = malloc(real_size);

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

  *out = str;

  return true;
}

bool
hsk_read_target(
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
    case HSK_INAME:
    case HSK_HNAME: {
      return hsk_read_compressed(data, data_len, st, &target->name);
    }
    default: {
      return false;
    }
  }
}

bool
hsk_read_host(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_target_t *target
) {
  uint8_t type;

  if (!read_u8(data, data_len, &type))
    return false;

  return hsk_read_target(data, data_len, type, st, target);
}

bool
hsk_read_host_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_host_record_t *rec
) {
  return hsk_read_host(data, data_len, st, &rec->target);
}

bool
hsk_read_txt_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_txt_record_t *rec
) {
  return hsk_read_compressed(data, data_len, st, &rec->text);
}

bool
hsk_read_service_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_service_record_t *rec
) {
  if (!hsk_read_compressed(data, data_len, st, &rec->service))
    goto fail;

  if (!hsk_read_compressed(data, data_len, st, &rec->protocol))
    goto fail;

  if (!read_u8(data, data_len, &rec->priority))
    goto fail;

  if (!read_u8(data, data_len, &rec->weight))
    goto fail;

  if (!hsk_read_host(data, data_len, st, &rec->target))
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
hsk_read_location_record(
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
hsk_read_magnet_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_magnet_record_t *rec
) {
  if (!hsk_read_compressed(data, data_len, st, &rec->nid))
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
hsk_read_ds_record(
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
hsk_read_tls_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_tls_record_t *rec
) {
  if (!hsk_read_compressed(data, data_len, st, &rec->protocol))
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
hsk_read_ssh_record(
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
hsk_read_pgp_record(
  uint8_t **data,
  size_t *data_len,
  hsk_pgp_record_t *rec
) {
  return hsk_read_ssh_record(data, data_len, (hsk_ssh_record_t *)rec);
}

bool
hsk_read_addr_record(
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
      if (!hsk_read_compressed(data, data_len, st, &rec->currency))
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
hsk_read_extra_record(
  uint8_t **data,
  size_t *data_len,
  hsk_extra_record_t *rec
) {
  uint8_t size;
  read_u8(data, data_len, &size);

  if (!alloc_bytes(data, data_len, &rec->data, size))
    return false;

  rec->data_len = size;

  return true;
}

void
hsk_init_record(hsk_record_t *r) {
  if (r == NULL)
    return;

  r->type = r->type;
  r->next = NULL;

  switch (r->type) {
    case HSK_INET4:
    case HSK_INET6:
    case HSK_ONION:
    case HSK_ONIONNG:
    case HSK_INAME:
    case HSK_HNAME:
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
hsk_alloc_record(uint8_t type) {
  hsk_record_t *r = NULL;

  switch (type) {
    case HSK_INET4:
    case HSK_INET6:
    case HSK_ONION:
    case HSK_ONIONNG:
    case HSK_INAME:
    case HSK_HNAME:
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

  r->type = type;
  r->next = NULL;

  hsk_init_record(r);
  return r;
}

void
hsk_free_record(hsk_record_t *r) {
  if (r == NULL)
    return;

  switch (r->type) {
    case HSK_INET4:
    case HSK_INET6:
    case HSK_ONION:
    case HSK_ONIONNG:
    case HSK_INAME:
    case HSK_HNAME:
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
hsk_free_records(hsk_record_t *records) {
  hsk_record_t *r, *n;
  for (r = records; r; r = n) {
    n = r->next;
    hsk_free_record(r);
  }
}

void
hsk_free_resource(hsk_resource_t *res) {
  if (res == NULL)
    return;
  hsk_free_records(res->records);
  free(res);
}

bool
hsk_read_record(
  uint8_t **data,
  size_t *data_len,
  uint8_t type,
  hsk_symbol_table_t *st,
  hsk_record_t **r
) {
  *r = hsk_alloc_record(type);

  if (r == NULL)
    return false;

  bool result = true;

  switch (type) {
    case HSK_INET4:
    case HSK_INET6:
    case HSK_ONION:
    case HSK_ONIONNG:
    case HSK_INAME:
    case HSK_HNAME: {
      hsk_host_record_t *rec = (hsk_host_record_t *)*r;
      result = hsk_read_target(data, data_len, type, st, &rec->target);
      break;
    }
    case HSK_CANONICAL:
    case HSK_DELEGATE:
    case HSK_NS: {
      hsk_host_record_t *rec = (hsk_host_record_t *)*r;
      result = hsk_read_host_record(data, data_len, st, rec);
      break;
    }
    case HSK_SERVICE: {
      hsk_service_record_t *rec = (hsk_service_record_t *)*r;
      result = hsk_read_service_record(data, data_len, st, rec);
      break;
    }
    case HSK_URL:
    case HSK_EMAIL:
    case HSK_TEXT: {
      hsk_txt_record_t *rec = (hsk_txt_record_t *)*r;
      result = hsk_read_txt_record(data, data_len, st, rec);
      break;
    }
    case HSK_LOCATION: {
      hsk_location_record_t *rec = (hsk_location_record_t *)*r;
      result = hsk_read_location_record(data, data_len, rec);
      break;
    }
    case HSK_MAGNET: {
      hsk_magnet_record_t *rec = (hsk_magnet_record_t *)*r;
      result = hsk_read_magnet_record(data, data_len, st, rec);
      break;
    }
    case HSK_DS: {
      hsk_ds_record_t *rec = (hsk_ds_record_t *)*r;
      result = hsk_read_ds_record(data, data_len, rec);
      break;
    }
    case HSK_TLS: {
      hsk_tls_record_t *rec = (hsk_tls_record_t *)*r;
      result = hsk_read_tls_record(data, data_len, st, rec);
      break;
    }
    case HSK_SSH:
    case HSK_PGP: {
      hsk_ssh_record_t *rec = (hsk_ssh_record_t *)*r;
      result = hsk_read_ssh_record(data, data_len, rec);
      break;
    }
    case HSK_ADDR: {
      hsk_addr_record_t *rec = (hsk_addr_record_t *)*r;
      result = hsk_read_addr_record(data, data_len, st, rec);
      break;
    }
    default: {
      hsk_extra_record_t *rec = (hsk_extra_record_t *)*r;
      result = hsk_read_extra_record(data, data_len, rec);
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
hsk_decode_resource(
  uint8_t *data,
  size_t data_len,
  hsk_resource_t **resource
) {
  bool result = true;

  hsk_symbol_table_t st;
  st.strings = NULL;
  st.sizes = NULL;
  st.size = 0;

  hsk_resource_t *res = malloc(sizeof(hsk_resource_t));

  if (res == NULL)
    goto fail;

  res->version = 0;
  res->ttl = 0;
  res->compat = false;
  res->records = NULL;

  if (!read_u8(&data, &data_len, &res->version))
    goto fail;

  if (res->version != 0)
    goto fail;

  uint16_t field;
  if (!read_u16(&data, &data_len, &field))
    goto fail;

  res->compat = (field & 0x8000) != 0;
  res->ttl = ((uint32_t)(field & 0x7fff)) << 6;

  uint8_t st_size;
  if (!read_u8(&data, &data_len, &st_size))
    goto fail;

  if (st_size != 0) {
    st.strings = (char **)malloc(st_size * sizeof(char *) + 1);
    st.sizes = (uint8_t *)malloc(st_size * sizeof(uint8_t) + 1);

    if (st.strings == NULL || st.sizes == NULL)
      goto fail;

    int32_t i;
    for (i = 0; i < st_size; i++) {
      uint8_t size;

      if (!read_u8(&data, &data_len, &size))
        goto fail;

      if (!alloc_ascii(&data, &data_len, &st.strings[i], size))
        goto fail;

      st.sizes[i] = size;
      st.size += 1;
    }

    st.strings[st_size] = NULL;
    st.sizes[st_size] = 0;
  }

  hsk_record_t *parent = NULL;

  while (data_len > 0) {
    hsk_record_t *record;
    uint8_t type;

    read_u8(&data, &data_len, &type);

    if (!hsk_read_record(&data, &data_len, type, &st, &record))
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
  hsk_free_resource(res);
  result = false;

done:
  if (st.size > 0) {
    int32_t i;
    for (i = 0; i < st.size; i++)
      free(st.strings[i]);
  }

  if (st.strings != NULL)
    free(st.strings);

  if (st.sizes != NULL)
    free(st.sizes);

  return result;
}
