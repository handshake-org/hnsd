#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <stdbool.h>

#include "bio.h"
#include "hsk-resource.h"
#include "hsk-error.h"

int32_t
hsk_read_string(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  char **out
) {
  uint8_t size;
  uint8_t *chunk;

  if (!read_u8(data, data_len, &size))
    return HSK_EENCODING;

  if (!slice_bytes(data, data_len, &chunk, size))
    return HSK_EENCODING;

  int32_t real_size = 0;
  int32_t i;

  for (i = 0; i < size; i++) {
    uint8_t ch = chunk[i];

    if (ch & 0x80) {
      uint8_t index = ch & 0x7f;
      if (index >= st->size)
        return HSK_EENCODING;
      real_size += st->sizes[index];
      continue;
    }

    // No DEL.
    if (ch == 0x7f)
      return HSK_EENCODING;

    // Any non-printable character can screw.
    // Tab, line feed, and carriage return all valid.
    if (ch < 0x20
        && ch != 0x09
        && ch != 0x0a
        && ch != 0x0d) {
      return HSK_EENCODING;
    }

    real_size += 1;
  }

  if (real_size > 512)
    return HSK_EENCODING;

  char *str = malloc(real_size);

  if (str == NULL)
    return HSK_ENOMEM;

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

  return HSK_SUCCESS;
}

int32_t
hsk_read_target(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_target_t *target
) {
  if (data == NULL || st == NULL || target == NULL)
    return HSK_EBADARGS;

  uint8_t type;

  if (!read_u8(data, data_len, &type))
    return HSK_EENCODING;

  target->type = type;
  target->name = NULL;

  switch (type) {
    case HSK_INET4: {
      if (!read_bytes(data, data_len, target->addr, 4))
        return HSK_EENCODING;

      break;
    }
    case HSK_INET6: {
      uint8_t field;

      if (!read_u8(data, data_len, &field))
        return HSK_EENCODING;

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

      if (!read_bytes(data, data_len, back, left))
        return HSK_EENCODING;

      break;
    }
    case HSK_ONION: {
      if (!read_bytes(data, data_len, target->addr, 10))
        return false;
      break;
    }
    case HSK_ONIONNG: {
      if (!read_bytes(data, data_len, target->addr, 33))
        return false;
      break;
    }
    case HSK_INAME:
    case HSK_HNAME: {
      int32_t rc = hsk_read_string(data, data_len, st, &target->name);
      if (rc != HSK_SUCCESS)
        return rc;
      break;
    }
    default: {
      return HSK_EENCODING;
    }
  }

  return HSK_SUCCESS;
}

int32_t
hsk_read_target_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_target_record_t **rec
) {
  *rec = malloc(sizeof(hsk_target_record_t));

  if (*rec == NULL)
    return HSK_ENOMEM;

  (*rec)->type = 0;
  (*rec)->next = NULL;
  (*rec)->target.name = NULL;

  int32_t rc = hsk_read_target(data, data_len, st, &(*rec)->target);

  if (rc != HSK_SUCCESS) {
    free(*rec);
    return rc;
  }

  return HSK_SUCCESS;
}

int32_t
hsk_read_txt_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_txt_record_t **rec
) {
  uint8_t size;

  if (!read_u8(data, data_len, &size))
    return HSK_EENCODING;

  if (*data_len < size)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_txt_record_t));

  if (*rec == NULL)
    return HSK_ENOMEM;

  (*rec)->type = 0;
  (*rec)->next = NULL;
  (*rec)->text = NULL;

  if (!alloc_ascii(data, data_len, &(*rec)->text, size)) {
    free(*rec);
    return HSK_EENCODING;
  }

  return HSK_SUCCESS;
}

int32_t
hsk_read_service_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_service_record_t **rec
) {
  *rec = malloc(sizeof(hsk_service_record_t));

  if (*rec == NULL)
    return HSK_ENOMEM;

  (*rec)->type = 0;
  (*rec)->next = NULL;
  (*rec)->target.name = NULL;
  (*rec)->service = NULL;
  (*rec)->protocol = NULL;

  int32_t rc = HSK_SUCCESS;

  rc = hsk_read_string(data, data_len, st, &(*rec)->service);

  if (rc != HSK_SUCCESS)
    goto fail;

  rc = hsk_read_string(data, data_len, st, &(*rec)->protocol);

  if (rc != HSK_SUCCESS)
    goto fail;

  rc = HSK_EENCODING;

  if (!read_u8(data, data_len, &(*rec)->priority))
    goto fail;

  if (!read_u8(data, data_len, &(*rec)->weight))
    goto fail;

  rc = hsk_read_target(data, data_len, st, &(*rec)->target);

  if (rc != HSK_SUCCESS)
    goto fail;

  rc = HSK_EENCODING;

  if (!read_u16(data, data_len, &(*rec)->port))
    goto fail;

  return HSK_SUCCESS;

fail:
  if (*rec) {
    if ((*rec)->service)
      free((*rec)->service);
    if ((*rec)->protocol)
      free((*rec)->protocol);
    if ((*rec)->target.name)
      free((*rec)->target.name);
    free(*rec);
  }

  return rc;
}

int32_t
hsk_read_location_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_location_record_t **rec
) {
  if (*data_len < 16)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_location_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;

  read_u8(data, data_len, &(*rec)->version);
  read_u8(data, data_len, &(*rec)->size);
  read_u8(data, data_len, &(*rec)->horiz_pre);
  read_u8(data, data_len, &(*rec)->vert_pre);
  read_u32(data, data_len, &(*rec)->latitude);
  read_u32(data, data_len, &(*rec)->longitude);
  read_u32(data, data_len, &(*rec)->altitude);

  return HSK_SUCCESS;
}

int32_t
hsk_read_magnet_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_magnet_record_t **rec
) {
  *rec = malloc(sizeof(hsk_magnet_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;
  (*rec)->nid = NULL;
  (*rec)->nin = NULL;

  int32_t rc = HSK_SUCCESS;

  rc = hsk_read_string(data, data_len, st, &(*rec)->nid);

  if (rc != HSK_SUCCESS)
    goto fail;

  uint8_t size;

  if (!read_u8(data, data_len, &size)) {
    rc = HSK_EENCODING;
    goto fail;
  }

  if (!alloc_bytes(data, data_len, &(*rec)->nin, size)) {
    rc = HSK_ENOMEM;
    goto fail;
  }

  (*rec)->nin_len = size;

  return HSK_SUCCESS;

fail:
  if (*rec) {
    if ((*rec)->nid)
      free((*rec)->nid);
    if ((*rec)->nin)
      free((*rec)->nin);
    free(*rec);
  }

  return rc;
}

int32_t
hsk_read_ds_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_ds_record_t **rec
) {
  if (*data_len < 5)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_ds_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;

  uint8_t size;
  read_u16(data, data_len, &(*rec)->key_tag);
  read_u8(data, data_len, &(*rec)->algorithm);
  read_u8(data, data_len, &(*rec)->digest_type);
  read_u8(data, data_len, &size);

  if (!alloc_bytes(data, data_len, &(*rec)->digest, size)) {
    free(*rec);
    return HSK_EENCODING;
  }

  (*rec)->digest_len = size;

  return HSK_SUCCESS;
}

int32_t
hsk_read_tls_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_tls_record_t **rec
) {
  *rec = malloc(sizeof(hsk_tls_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;
  (*rec)->protocol = NULL;
  (*rec)->certificate = NULL;

  int32_t rc = HSK_SUCCESS;

  rc = hsk_read_string(data, data_len, st, &(*rec)->protocol);

  if (rc != HSK_SUCCESS)
    goto fail;

  if (*data_len < 6) {
    rc = HSK_EENCODING;
    goto fail;
  }

  uint8_t size;
  read_u16(data, data_len, &(*rec)->port);
  read_u8(data, data_len, &(*rec)->usage);
  read_u8(data, data_len, &(*rec)->selector);
  read_u8(data, data_len, &(*rec)->matching_type);
  read_u8(data, data_len, &size);

  if (!alloc_bytes(data, data_len, &(*rec)->certificate, size)) {
    rc = HSK_EENCODING;
    goto fail;
  }

  (*rec)->certificate_len = size;

  return HSK_SUCCESS;

fail:
  if (*rec) {
    if ((*rec)->protocol)
      free((*rec)->protocol);
    if ((*rec)->certificate)
      free((*rec)->certificate);
    free(*rec);
  }

  return rc;
}

int32_t
hsk_read_ssh_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_ssh_record_t **rec
) {
  if (*data_len < 3)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_ssh_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;

  uint8_t size;
  read_u8(data, data_len, &(*rec)->algorithm);
  read_u8(data, data_len, &(*rec)->key_type);
  read_u8(data, data_len, &size);

  if (!alloc_bytes(data, data_len, &(*rec)->fingerprint, size)) {
    free(rec);
    return HSK_EENCODING;
  }

  (*rec)->fingerprint_len = size;

  return HSK_SUCCESS;
}

int32_t
hsk_read_pgp_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_pgp_record_t **rec
) {
  return hsk_read_ssh_record(data, data_len, st, (hsk_ssh_record_t **)&rec);
}

int32_t
hsk_read_addr_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_addr_record_t **rec
) {
  if (*data_len < 3)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_addr_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;
  (*rec)->currency = NULL;
  (*rec)->address = NULL;
  (*rec)->hash = NULL;

  uint8_t type;

  if (!read_u8(data, data_len, &type))
    return HSK_EENCODING;

  (*rec)->ctype = type;

  switch (type) {
    case 0: {
      int32_t rc = hsk_read_string(data, data_len, st, &(*rec)->currency);

      if (rc != HSK_SUCCESS) {
        free(*rec);
        return rc;
      }

      uint8_t size;

      if (!read_u8(data, data_len, &size)) {
        free((*rec)->currency);
        free(*rec);
        return HSK_EENCODING;
      }

      if (!alloc_ascii(data, data_len, &(*rec)->address, size)) {
        free((*rec)->currency);
        free(*rec);
        return HSK_ENOMEM;
      }

      break;
    }
    case 1:
    case 2: { // HSK / BTC
      uint8_t field;

      if (!read_u8(data, data_len, &field)) {
        free(*rec);
        return HSK_EENCODING;
      }

      (*rec)->testnet = (field & 0x80) != 0;

      if (!read_u8(data, data_len, &(*rec)->version))
        return HSK_EENCODING;

      uint8_t size = (field & 0x7f) + 1;

      if (!alloc_bytes(data, data_len, &(*rec)->hash, size)) {
        free(*rec);
        return HSK_EENCODING;
      }

      (*rec)->hash_len = size;

      if (type == 1)
        (*rec)->currency = strdup("hsk");
      else
        (*rec)->currency = strdup("btc");

      if ((*rec)->currency == NULL) {
        free((*rec)->hash);
        free(*rec);
        return HSK_ENOMEM;
      }

      break;
    }
    case 3: { // ETH
      if (*data_len < 20) {
        free(*rec);
        return HSK_ENOMEM;
      }

      (*rec)->currency = strdup("eth");

      if ((*rec)->currency == NULL) {
        free(*rec);
        return HSK_ENOMEM;
      }

      if (!alloc_bytes(data, data_len, &(*rec)->hash, 20)) {
        free((*rec)->currency);
        free(*rec);
        return HSK_ENOMEM;
      }

      (*rec)->hash_len = 20;

      break;
    }
  }

  return HSK_SUCCESS;
}

int32_t
hsk_read_extra_record(
  uint8_t **data,
  size_t *data_len,
  hsk_symbol_table_t *st,
  hsk_extra_record_t **rec
) {
  if (*data_len < 1)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_extra_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = HSK_EXTRA;
  (*rec)->next = NULL;
  (*rec)->data = NULL;

  uint8_t size;
  read_u8(data, data_len, &size);

  if (!alloc_bytes(data, data_len, &(*rec)->data, size)) {
    free(*rec);
    return HSK_EENCODING;
  }

  (*rec)->data_len = size;

  return HSK_SUCCESS;
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
      hsk_target_record_t *rec = (hsk_target_record_t *)r;
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
      r = (hsk_record_t *)malloc(sizeof(hsk_target_record_t));
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
      hsk_target_record_t *rec = (hsk_target_record_t *)r;
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
    case HSK_SSH: {
      hsk_ssh_record_t *rec = (hsk_ssh_record_t *)r;
      if (rec->fingerprint)
        free(rec->fingerprint);
      free(rec);
      break;
    }
    case HSK_PGP: {
      hsk_pgp_record_t *rec = (hsk_pgp_record_t *)r;
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
hsk_free_resource(hsk_resource_t *rs) {
  if (rs == NULL)
    return;
  hsk_free_records(rs->records);
  free(rs);
}

int32_t
hsk_parse_resource(
  uint8_t *data,
  size_t data_len,
  hsk_resource_t **res
) {
  if (data_len < 1)
    return HSK_EENCODING;

  uint8_t version = *data;
  data += 1;
  data_len -= 1;

  if (version != 0)
    return HSK_EENCODING;

  if (data_len < 2)
    return HSK_EENCODING;

  uint8_t field = (data[1] << 8) | data[0];
  bool compat = (field & 0x8000) != 0;
  uint32_t ttl = (field & 0x7fff) << 6;
  data += 2;
  data_len -= 2;

  if (data_len < 1)
    return HSK_EENCODING;

  hsk_resource_t *r = NULL;
  uint8_t st_size = *data;
  data += 1;
  data_len -= 1;

  hsk_symbol_table_t st;
  st.strings = NULL;
  st.sizes = NULL;
  st.size = 0;

  hsk_record_t *head = NULL;

  int32_t code = HSK_SUCCESS;

  if (st_size != 0) {
    if (data_len < 1)
      return HSK_EENCODING;

    st.strings = (char **)malloc(st_size * sizeof(char *) + 1);
    st.sizes = (uint8_t *)malloc(st_size * sizeof(uint8_t) + 1);

    if (st.strings == NULL || st.sizes == NULL) {
      code = HSK_ENOMEM;
      goto fail;
    }

    int32_t i;
    for (i = 0; i < st_size; i++) {
      if (data_len < 1)
        return HSK_EENCODING;

      uint8_t size = *data;
      data += 1;
      data_len -= 1;

      if (data_len < size) {
        code = HSK_EENCODING;
        goto fail;
      }

      st.strings[i] = (char *)malloc(size * sizeof(char) + 1);
      st.sizes[i] = size;

      if (st.strings[i] == NULL) {
        code = HSK_ENOMEM;
        goto fail;
      }

      st.size += 1;

      int32_t j;
      for (j = 0; j < size; j++) {
        uint8_t ch = data[j];

        // No unicode.
        if (ch & 0x80) {
          code = HSK_EENCODING;
          goto fail;
        }

        // No DEL.
        if (ch == 0x7f) {
          code = HSK_EENCODING;
          goto fail;
        }

        // Any non-printable character can screw.
        // Tab, line feed, and carriage return all valid.
        if (ch < 0x20
            && ch != 0x09
            && ch != 0x0a
            && ch != 0x0d) {
          code = HSK_EENCODING;
          goto fail;
        }
      }

      memcpy(st.strings[i], data, size);
      st.strings[i][size] = '\0';

      data += size;
      data_len -= size;
    }

    st.strings[st_size] = NULL;
    st.sizes[st_size] = 0;
  }

  r = malloc(sizeof(hsk_resource_t));

  if (r == NULL) {
    code = HSK_ENOMEM;
    goto fail;
  }

  r->version = version;
  r->ttl = ttl;
  r->compat = compat;
  r->records = NULL;

  hsk_record_t *p = NULL;

  while (data_len > 0) {
    uint8_t type = *data;

    data += 1;
    data_len -= 1;
    hsk_record_t *r = NULL;

    switch (type) {
      case HSK_INET4:
      case HSK_INET6:
      case HSK_ONION:
      case HSK_ONIONNG:
      case HSK_INAME:
      case HSK_HNAME:
        data -= 1;
        data_len += 1;
        // fall through
      case HSK_CANONICAL:
      case HSK_DELEGATE:
      case HSK_NS: {
        hsk_target_record_t *rec;

        int32_t rc = hsk_read_target_record(&data, &data_len, &st, &rec);

        if (rc != HSK_SUCCESS) {
          code = rc;
          goto fail;
        }

        rec->type = type;
        r = (hsk_record_t *)rec;

        break;
      }
      case HSK_SERVICE: {
        hsk_service_record_t *rec;

        int32_t rc = hsk_read_service_record(&data, &data_len, &st, &rec);

        if (rc != HSK_SUCCESS) {
          code = rc;
          goto fail;
        }

        rec->type = type;
        r = (hsk_record_t *)rec;

        break;
      }
      case HSK_URL:
      case HSK_EMAIL:
      case HSK_TEXT: {
        hsk_txt_record_t *rec;

        int32_t rc = hsk_read_txt_record(&data, &data_len, &st, &rec);

        if (rc != HSK_SUCCESS) {
          code = rc;
          goto fail;
        }

        rec->type = type;
        r = (hsk_record_t *)rec;

        break;
      }
      case HSK_LOCATION: {
        hsk_location_record_t *rec;

        int32_t rc = hsk_read_location_record(&data, &data_len, &st, &rec);

        if (rc != HSK_SUCCESS) {
          code = rc;
          goto fail;
        }

        rec->type = type;
        r = (hsk_record_t *)rec;

        break;
      }
      case HSK_MAGNET: {
        hsk_magnet_record_t *rec;

        int32_t rc = hsk_read_magnet_record(&data, &data_len, &st, &rec);

        if (rc != HSK_SUCCESS) {
          code = rc;
          goto fail;
        }

        rec->type = type;
        r = (hsk_record_t *)rec;

        break;
      }
      case HSK_DS: {
        hsk_ds_record_t *rec;

        int32_t rc = hsk_read_ds_record(&data, &data_len, &st, &rec);

        if (rc != HSK_SUCCESS) {
          code = rc;
          goto fail;
        }

        rec->type = type;
        r = (hsk_record_t *)rec;

        break;
      }
      case HSK_TLS: {
        hsk_tls_record_t *rec;

        int32_t rc = hsk_read_tls_record(&data, &data_len, &st, &rec);

        if (rc != HSK_SUCCESS) {
          code = rc;
          goto fail;
        }

        rec->type = type;
        r = (hsk_record_t *)rec;

        break;
      }
      case HSK_SSH: {
        hsk_ssh_record_t *rec;

        int32_t rc = hsk_read_ssh_record(&data, &data_len, &st, &rec);

        if (rc != HSK_SUCCESS) {
          code = rc;
          goto fail;
        }

        rec->type = type;
        r = (hsk_record_t *)rec;

        break;
      }
      case HSK_PGP: {
        hsk_pgp_record_t *rec;

        int32_t rc = hsk_read_pgp_record(&data, &data_len, &st, &rec);

        if (rc != HSK_SUCCESS) {
          code = rc;
          goto fail;
        }

        rec->type = type;
        r = (hsk_record_t *)rec;

        break;
      }
      case HSK_ADDR: {
        hsk_addr_record_t *rec;

        int32_t rc = hsk_read_addr_record(&data, &data_len, &st, &rec);

        if (rc != HSK_SUCCESS) {
          code = rc;
          goto fail;
        }

        rec->type = type;
        r = (hsk_record_t *)rec;

        break;
      }
      default: {
        hsk_extra_record_t *rec;

        int32_t rc = hsk_read_extra_record(&data, &data_len, &st, &rec);

        if (rc != HSK_SUCCESS) {
          code = rc;
          goto fail;
        }

        rec->rtype = type;
        r = (hsk_record_t *)rec;

        break;
      }
    }

    if (head == NULL)
      head = r;

    if (p)
      p->next = r;

    p = r;
  }

  r->records = head;

  *res = r;

  goto done;

fail:
  if (r != NULL)
    free(r);

  if (head != NULL)
    hsk_free_records(head);

done:
  if (st.size > 0) {
    int32_t i = st.size;
    while (i--)
      free(st.strings[i]);
  }

  if (st.strings != NULL)
    free(st.strings);

  if (st.sizes != NULL)
    free(st.sizes);

  return code;
}
