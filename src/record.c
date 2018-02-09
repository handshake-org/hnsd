#include <strings.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <limits.h>
#include <stdbool.h>
#include <errno.h>
#include <ctype.h>

#include "record.h"
#include "errors.h"

int32_t
hsk_read_string(
  uint8_t *data,
  size_t data_len,
  hsk_symbol_table_t *st,
  char **out,
  uint8_t **odata,
  size_t *odata_len
) {
  if (data == NULL || st == NULL || out == NULL)
    return HSK_EBADARGS;

  if (data_len < 1)
    return HSK_EENCODING;

  uint8_t size = *data;
  data += 1;
  data_len -= 1;

  if (data_len < size)
    return HSK_EENCODING;

  int32_t real_size = 0;
  int32_t i;

  for (i = 0; i < size; i++) {
    uint8_t ch = data[i];

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
    uint8_t ch = data[i];

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

  data += size;
  data_len -= size;

  *out = str;

  if (odata)
    *odata = data;

  if (odata_len)
    *odata_len = data_len;

  return HSK_SUCCESS;
}

int32_t
hsk_parse_target(
  uint8_t *data,
  size_t data_len,
  hsk_symbol_table_t *st,
  hsk_target_t *target,
  uint8_t **odata,
  size_t *odata_len
) {
  if (data == NULL || st == NULL || target == NULL)
    return HSK_EBADARGS;

  if (data_len < 1)
    return HSK_EENCODING;

  uint8_t type = *data;
  data += 1;
  data_len -= 1;

  target->type = type;
  target->name = NULL;

  switch (type) {
    case HSK_INET4: {
      if (data_len < 4)
        return HSK_EENCODING;

      memcpy(target->addr, data, 4);
      data += 4;
      data_len -= 4;

      break;
    }
    case HSK_INET6: {
      if (data_len < 1)
        return HSK_EENCODING;

      uint8_t field = *data;
      data += 1;
      data_len -= 1;

      uint8_t start = field >> 4;
      uint8_t len = field & 0x0f;
      uint8_t left = 16 - (start + len);

      if (data_len < start)
        return HSK_EENCODING;

      // Front half.
      memcpy(target->addr, data, start);
      data += start;
      data_len -= start;

      // Fill in the missing section.
      memset(target->addr + start, 0x00, len);

      if (data_len < left)
        return HSK_EENCODING;

      // Back half.
      memcpy(target->addr + start + len, data, left);
      data += left;
      data_len -= left;

      break;
    }
    case HSK_ONION: {
      if (data_len < 10)
        return HSK_EENCODING;

      memcpy(target->addr, data, 10);
      data += 10;
      data_len -= 10;

      break;
    }
    case HSK_ONIONNG: {
      if (data_len < 33)
        return HSK_EENCODING;

      memcpy(target->addr, data, 33);
      data += 33;
      data_len -= 33;

      break;
    }
    case HSK_INAME:
    case HSK_HNAME: {
      int32_t rc = hsk_read_string(
        data, data_len, st, &target->name, &data, &data_len);
      if (rc != HSK_SUCCESS)
        return rc;
      break;
    }
    default: {
      return HSK_EENCODING;
    }
  }

  if (odata)
    *odata = data;

  if (odata_len)
    *odata_len = data_len;

  return HSK_SUCCESS;
}

int32_t
hsk_parse_target_record(
  uint8_t *data,
  size_t data_len,
  hsk_symbol_table_t *st,
  hsk_target_record_t **rec,
  uint8_t **odata,
  size_t *odata_len
) {
  if (data_len < 1)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_target_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;
  (*rec)->target.name = NULL;

  int32_t rc = hsk_parse_target(
    data, data_len, st, &(*rec)->target, &data, &data_len);

  if (rc != HSK_SUCCESS) {
    free(*rec);
    return rc;
  }

  if (odata)
    *odata = data;

  if (odata_len)
    *odata_len = data_len;

  return HSK_SUCCESS;
}

int32_t
hsk_parse_txt_record(
  uint8_t *data,
  size_t data_len,
  hsk_symbol_table_t *st,
  hsk_txt_record_t **rec,
  uint8_t **odata,
  size_t *odata_len
) {
  if (data_len < 1)
    return HSK_EENCODING;

  uint8_t size = *data;
  data += 1;
  data_len -= 1;

  if (data_len < size)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_txt_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;
  (*rec)->text = malloc(size * sizeof(char) + 1);

  if ((*rec)->text == NULL) {
    free(*rec);
    return HSK_ENOMEM;
  }

  memcpy((*rec)->text, data, size);
  data += size;
  data_len -= size;

  if (odata)
    *odata = data;

  if (odata_len)
    *odata_len = data_len;

  return HSK_SUCCESS;
}

int32_t
hsk_parse_service_record(
  uint8_t *data,
  size_t data_len,
  hsk_symbol_table_t *st,
  hsk_service_record_t **rec,
  uint8_t **odata,
  size_t *odata_len
) {
  if (data_len < 1)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_service_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;
  (*rec)->target.name = NULL;
  (*rec)->service = NULL;
  (*rec)->protocol = NULL;

  int32_t rc = HSK_SUCCESS;

  rc = hsk_read_string(
    data, data_len, st, &(*rec)->service, &data, &data_len);

  if (rc != HSK_SUCCESS)
    goto fail;

  rc = hsk_read_string(
    data, data_len, st, &(*rec)->protocol, &data, &data_len);

  if (rc != HSK_SUCCESS)
    goto fail;

  if (data_len < 2) {
    rc = HSK_EENCODING;
    goto fail;
  }

  (*rec)->priority = *data;
  data += 1;
  data_len -= 1;

  (*rec)->weight = *data;
  data += 1;
  data_len -= 1;

  rc = hsk_parse_target(
    data, data_len, st, &(*rec)->target, &data, &data_len);

  if (rc != HSK_SUCCESS)
    goto fail;

  if (data_len < 2) {
    rc = HSK_EENCODING;
    goto fail;
  }

  (*rec)->port = (data[1] << 8) | data[0];
  data += 2;
  data_len -= 2;

  if (odata)
    *odata = data;

  if (odata_len)
    *odata_len = data_len;

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
hsk_parse_location_record(
  uint8_t *data,
  size_t data_len,
  hsk_symbol_table_t *st,
  hsk_location_record_t **rec,
  uint8_t **odata,
  size_t *odata_len
) {
  if (data_len < 16)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_location_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;

  (*rec)->version = data[0];
  (*rec)->size = data[1];
  (*rec)->horiz_pre = data[2];
  (*rec)->vert_pre = data[3];
  (*rec)->latitude = (data[7] << 24) | (data[6] << 16) | (data[5] << 8) | data[4];
  (*rec)->longitude = (data[11] << 24) | (data[10] << 16) | (data[9] << 8) | data[8];
  (*rec)->altitude = (data[15] << 24) | (data[14] << 16) | (data[13] << 8) | data[12];

  data += 16;
  data_len -= 16;

  if (odata)
    *odata = data;

  if (odata_len)
    *odata_len = data_len;

  return HSK_SUCCESS;
}

int32_t
hsk_parse_magnet_record(
  uint8_t *data,
  size_t data_len,
  hsk_symbol_table_t *st,
  hsk_magnet_record_t **rec,
  uint8_t **odata,
  size_t *odata_len
) {
  if (data_len < 1)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_magnet_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;
  (*rec)->nid = NULL;
  (*rec)->nin = NULL;

  int32_t rc = HSK_SUCCESS;

  rc = hsk_read_string(
    data, data_len, st, &(*rec)->nid, &data, &data_len);

  if (rc != HSK_SUCCESS)
    goto fail;

  if (data_len < 1) {
    rc = HSK_EENCODING;
    goto fail;
  }

  uint8_t size = *data;
  data += 1;
  data_len -= 1;

  if (data_len < size) {
    rc = HSK_EENCODING;
    goto fail;
  }

  (*rec)->nin = malloc(size);

  if ((*rec)->nin == NULL) {
    rc = HSK_ENOMEM;
    goto fail;
  }

  memcpy((*rec)->nin, data, size);
  data += size;
  data_len -= size;

  if (odata)
    *odata = data;

  if (odata_len)
    *odata_len = data_len;

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
hsk_parse_ds_record(
  uint8_t *data,
  size_t data_len,
  hsk_symbol_table_t *st,
  hsk_ds_record_t **rec,
  uint8_t **odata,
  size_t *odata_len
) {
  if (data_len < 5)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_ds_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;

  (*rec)->key_tag = (data[1] << 8) | data[0];
  (*rec)->algorithm = data[2];
  (*rec)->digest_type = data[3];

  uint8_t size = data[4];
  data += 5;
  data_len -= 5;

  if (data_len < size) {
    free(*rec);
    return HSK_EENCODING;
  }

  (*rec)->digest = malloc(size);

  if ((*rec)->digest == NULL) {
    free(*rec);
    return HSK_ENOMEM;
  }

  memcpy((*rec)->digest, data, size);
  data += size;
  data_len -= size;

  if (odata)
    *odata = data;

  if (odata_len)
    *odata_len = data_len;

  return HSK_SUCCESS;
}

int32_t
hsk_parse_tls_record(
  uint8_t *data,
  size_t data_len,
  hsk_symbol_table_t *st,
  hsk_tls_record_t **rec,
  uint8_t **odata,
  size_t *odata_len
) {
  if (data_len < 1)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_tls_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;
  (*rec)->protocol = NULL;
  (*rec)->certificate = NULL;

  int32_t rc = HSK_SUCCESS;

  rc = hsk_read_string(
    data, data_len, st, &(*rec)->protocol, &data, &data_len);

  if (rc != HSK_SUCCESS)
    goto fail;

  if (data_len < 6) {
    rc = HSK_EENCODING;
    goto fail;
  }

  (*rec)->port = (data[1] << 8) | data[0];
  data += 2;
  data_len -= 2;

  (*rec)->usage = *data;
  data += 1;
  data_len -= 1;

  (*rec)->selector = *data;
  data += 1;
  data_len -= 1;

  (*rec)->matching_type = *data;
  data += 1;
  data_len -= 1;

  uint8_t size = *data;
  data += 1;
  data_len -= 1;

  if (data_len < size) {
    rc = HSK_EENCODING;
    goto fail;
  }

  (*rec)->certificate = malloc(size);

  if ((*rec)->certificate == NULL) {
    rc = HSK_ENOMEM;
    goto fail;
  }

  memcpy((*rec)->certificate, data, size);
  data += size;
  data_len -= size;

  if (odata)
    *odata = data;

  if (odata_len)
    *odata_len = data_len;

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
hsk_parse_ssh_record(
  uint8_t *data,
  size_t data_len,
  hsk_symbol_table_t *st,
  hsk_ssh_record_t **rec,
  uint8_t **odata,
  size_t *odata_len
) {
  if (data_len < 3)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_ssh_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;

  (*rec)->algorithm = data[0];
  (*rec)->key_type = data[1];

  uint8_t size = data[2];
  data += 3;
  data_len -= 3;

  if (data_len < size) {
    free(*rec);
    return HSK_EENCODING;
  }

  (*rec)->fingerprint = malloc(size);

  if ((*rec)->fingerprint == NULL) {
    free(*rec);
    return HSK_ENOMEM;
  }

  memcpy((*rec)->fingerprint, data, size);
  data += size;
  data_len -= size;

  if (odata)
    *odata = data;

  if (odata_len)
    *odata_len = data_len;

  return HSK_SUCCESS;
}

int32_t
hsk_parse_pgp_record(
  uint8_t *data,
  size_t data_len,
  hsk_symbol_table_t *st,
  hsk_pgp_record_t **rec,
  uint8_t **odata,
  size_t *odata_len
) {
  if (data_len < 3)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_pgp_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;

  (*rec)->algorithm = data[0];
  (*rec)->key_type = data[1];

  uint8_t size = data[2];
  data += 3;
  data_len -= 3;

  if (data_len < size) {
    free(*rec);
    return HSK_EENCODING;
  }

  (*rec)->fingerprint = malloc(size);

  if ((*rec)->fingerprint == NULL) {
    free(*rec);
    return HSK_ENOMEM;
  }

  memcpy((*rec)->fingerprint, data, size);
  data += size;
  data_len -= size;

  if (odata)
    *odata = data;

  if (odata_len)
    *odata_len = data_len;

  return HSK_SUCCESS;
}

int32_t
hsk_parse_addr_record(
  uint8_t *data,
  size_t data_len,
  hsk_symbol_table_t *st,
  hsk_addr_record_t **rec,
  uint8_t **odata,
  size_t *odata_len
) {
  if (data_len < 3)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_addr_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = 0;
  (*rec)->next = NULL;
  (*rec)->currency = NULL;
  (*rec)->address = NULL;
  (*rec)->hash = NULL;

  uint8_t type = *data;
  data += 1;
  data_len -= 1;

  (*rec)->ctype = type;

  switch (type) {
    case 0: {
      int32_t rc = hsk_read_string(
        data, data_len, st, &(*rec)->currency, &data, &data_len);

      if (rc != HSK_SUCCESS) {
        free(*rec);
        return rc;
      }

      if (data_len < 1) {
        free(*rec);
        return HSK_EENCODING;
      }

      uint8_t size = *data;
      data += 1;
      data_len -= 1;

      if (data_len < size) {
        free(*rec);
        return HSK_EENCODING;
      }

      (*rec)->currency = malloc(size);

      if ((*rec)->address == NULL) {
        free((*rec)->currency);
        free(*rec);
        return HSK_ENOMEM;
      }

      memcpy((*rec)->address, data, size);
      data += size;
      data_len -= size;

      break;
    }
    case 1:
    case 2: { // HSK / BTC
      uint8_t field = *data;
      data += 1;
      data_len -= 1;

      (*rec)->testnet = (field & 0x80) != 0;

      (*rec)->version = *data;
      data += 1;
      data_len -= 1;

      uint8_t size = (field & 0x7f) + 1;

      if (data_len < size) {
        free(*rec);
        return HSK_EENCODING;
      }

      (*rec)->hash = malloc(size);

      if ((*rec)->hash == NULL) {
        free(*rec);
        return HSK_EENCODING;
      }

      memcpy((*rec)->hash, data, size);
      data += size;
      data_len -= size;

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
      if (data_len < 20) {
        free(*rec);
        return HSK_ENOMEM;
      }

      (*rec)->currency = strdup("eth");

      if ((*rec)->currency == NULL) {
        free(*rec);
        return HSK_ENOMEM;
      }

      (*rec)->hash = malloc(20);

      if ((*rec)->hash == NULL) {
        free((*rec)->currency);
        free(*rec);
        return HSK_EENCODING;
      }

      memcpy((*rec)->hash, data, 20);
      data += 20;
      data_len -= 20;

      break;
    }
  }

  if (odata)
    *odata = data;

  if (odata_len)
    *odata_len = data_len;

  return HSK_SUCCESS;
}

int32_t
hsk_parse_extra_record(
  uint8_t *data,
  size_t data_len,
  hsk_symbol_table_t *st,
  hsk_extra_record_t **rec,
  uint8_t **odata,
  size_t *odata_len
) {
  if (data_len < 1)
    return HSK_EENCODING;

  *rec = malloc(sizeof(hsk_extra_record_t));

  if (*rec == NULL)
    return HSK_EENCODING;

  (*rec)->type = HSK_EXTRA;
  (*rec)->next = NULL;
  (*rec)->data = NULL;

  uint16_t size = *data;

  data += 1;
  data_len -= 1;

  if (data_len < size) {
    free(*rec);
    return HSK_EENCODING;
  }

  (*rec)->data = malloc(size);

  if ((*rec)->data == NULL) {
    free(*rec);
    return HSK_ENOMEM;
  }

  memcpy((*rec)->data, data, size);

  data += size;
  data_len -= size;

  if (odata)
    *odata = data;

  if (odata_len)
    *odata_len = data_len;

  return HSK_SUCCESS;
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
      st.size += 1;

      if (st.strings[i] == NULL) {
        code = HSK_ENOMEM;
        goto fail;
      }

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

        int32_t rc = hsk_parse_target_record(
          data, data_len, &st, &rec, &data, &data_len);

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

        int32_t rc = hsk_parse_service_record(
          data, data_len, &st, &rec, &data, &data_len);

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

        int32_t rc = hsk_parse_txt_record(
          data, data_len, &st, &rec, &data, &data_len);

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

        int32_t rc = hsk_parse_location_record(
          data, data_len, &st, &rec, &data, &data_len);

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

        int32_t rc = hsk_parse_magnet_record(
          data, data_len, &st, &rec, &data, &data_len);

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

        int32_t rc = hsk_parse_ds_record(
          data, data_len, &st, &rec, &data, &data_len);

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

        int32_t rc = hsk_parse_tls_record(
          data, data_len, &st, &rec, &data, &data_len);

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

        int32_t rc = hsk_parse_ssh_record(
          data, data_len, &st, &rec, &data, &data_len);

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

        int32_t rc = hsk_parse_pgp_record(
          data, data_len, &st, &rec, &data, &data_len);

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

        int32_t rc = hsk_parse_addr_record(
          data, data_len, &st, &rec, &data, &data_len);

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

        int32_t rc = hsk_parse_extra_record(
          data, data_len, &st, &rec, &data, &data_len);

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
