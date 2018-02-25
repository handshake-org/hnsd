#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <stdint.h>
#include <limits.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <errno.h>
#include <ctype.h>

#include "bio.h"
#include "dns.h"

int32_t
hsk_dns_name_cmp(char *a, char *b) {
  if (a == NULL && b == NULL)
    return 0;

  if (a == NULL)
    return -1;

  if (b == NULL)
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

int32_t
hsk_dns_parse_name(
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

          switch (b) {
            case 0x2e /*.*/:
            case 0x28 /*(*/:
            case 0x29 /*)*/:
            case 0x3b /*;*/:
            case 0x20 /* */:
            case 0x40 /*@*/:
            case 0x22 /*"*/:
            case 0x5c /*\\*/: {
              if (noff + 2 >= max)
                return -1;

              if (name) {
                name[noff + 0] = '\\';
                name[noff + 1] = b;
              }

              noff += 2;
              max += 1;

              break;
            }

            default: {
              if (b < 0x20 || b > 0x7e) {
                if (noff + 4 >= max)
                  return -1;

                if (name) {
                  char *fmt = "\\%u";
                  if (b < 10)
                    fmt = "\\00%u";
                  else if (b < 100)
                    fmt = "\\0%u";
                  sprintf(name + noff, fmt, (uint32_t)b);
                }

                noff += 4;
                max += 3;
              } else {
                if (noff + 1 >= max)
                  return -1;

                if (name)
                  name[noff] = b;

                noff += 1;
              }

              break;
            }
          }
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

  if (noff >= max)
    return -1;

  if (name)
    name[noff] = '\0';

  *data_ += res;
  *data_len_ -= res;

  return noff;
}

bool
hsk_dns_read_name(
  uint8_t **data,
  size_t *data_len,
  uint8_t *pd,
  size_t pd_len,
  char *name
) {
  return hsk_dns_parse_name(data, data_len, pd, pd_len, name) != -1;
}

int32_t
hsk_dns_size_name(uint8_t *data, size_t data_len, uint8_t *pd, size_t pd_len) {
  return hsk_dns_parse_name(&data, &data_len, pd, pd_len, NULL);
}

bool
hsk_dns_alloc_name(
  uint8_t **data,
  size_t *data_len,
  uint8_t *pd,
  size_t pd_len,
  char **name
) {
  int32_t size = hsk_dns_size_name(*data, *data_len, pd, pd_len);

  if (size == -1)
    return false;

  *name = malloc(size + 1);

  if (*name == NULL)
    return false;

  assert(hsk_dns_read_name(data, data_len, pd, pd_len, *name));

  return true;
}

void
hsk_dns_message_init(hsk_dns_message_t *msg) {
  if (msg == NULL)
    return;

  msg->id = 0;
  msg->flags = 0;
  msg->qdcount = 0;
  msg->ancount = 0;
  msg->nscount = 0;
  msg->arcount = 0;
  msg->question = NULL;
  msg->answer = NULL;
  msg->authority = NULL;
  msg->additional = NULL;
}

void
hsk_dns_question_init(hsk_dns_question_t *qs) {
  if (qs == NULL)
    return;

  qs->name = NULL;
  qs->type = 0;
  qs->class = 0;
  qs->next = NULL;
}

void
hsk_dns_record_init(hsk_dns_record_t *rr) {
  if (rr == NULL)
    return;

  rr->name = NULL;
  rr->type = 0;
  rr->class = 0;
  rr->ttl = 0;
  rr->rd = NULL;
  rr->next = NULL;
}

void
hsk_dns_text_init(hsk_dns_text_t *text) {
  if (text == NULL)
    return;

  text->data_len = 0;
  text->data = NULL;
  text->next = NULL;
}

hsk_dns_message_t *
hsk_dns_message_alloc(void) {
  hsk_dns_message_t *msg = malloc(sizeof(hsk_dns_message_t));
  hsk_dns_message_init(msg);
  return msg;
}

hsk_dns_question_t *
hsk_dns_question_alloc(void) {
  hsk_dns_question_t *qs = malloc(sizeof(hsk_dns_question_t));
  hsk_dns_question_init(qs);
  return qs;
}

hsk_dns_record_t *
hsk_dns_record_alloc(void) {
  hsk_dns_record_t *rr = malloc(sizeof(hsk_dns_record_t));
  hsk_dns_record_init(rr);
  return rr;
}

hsk_dns_text_t *
hsk_dns_text_alloc(void) {
  hsk_dns_text_t *text = malloc(sizeof(hsk_dns_text_t));
  hsk_dns_text_init(text);
  return text;
}

void
hsk_dns_question_free(hsk_dns_question_t *qs) {
  if (qs == NULL)
    return;

  if (qs->name)
    free(qs->name);

  free(qs);
}

void
hsk_dns_record_free(hsk_dns_record_t *rr) {
  if (rr == NULL)
    return;

  if (rr->name)
    free(rr->name);

  if (rr->rd)
    hsk_dns_rd_free(rr->type, rr->rd);

  free(rr);
}

void
hsk_dns_question_free_list(hsk_dns_question_t *qs) {
  hsk_dns_question_t *c, *n;
  for (c = qs; c; c = n) {
    n = c->next;
    hsk_dns_question_free(c);
  }
}

void
hsk_dns_record_free_list(hsk_dns_record_t *rr) {
  hsk_dns_record_t *c, *n;
  for (c = rr; c; c = n) {
    n = c->next;
    hsk_dns_record_free(c);
  }
}

void
hsk_dns_message_free(hsk_dns_message_t *msg) {
  if (msg == NULL)
    return;

  hsk_dns_question_free_list(msg->question);
  hsk_dns_record_free_list(msg->answer);
  hsk_dns_record_free_list(msg->authority);
  hsk_dns_record_free_list(msg->additional);
  free(msg);
}

void
hsk_dns_text_free(hsk_dns_text_t *text) {
  if (text == NULL)
    return;

  if (text->data)
    free(text->data);

  free(text);
}

void
hsk_dns_text_free_list(hsk_dns_text_t *text) {
  hsk_dns_text_t *c, *n;
  for (c = text; c; c = n) {
    n = c->next;
    hsk_dns_text_free(c);
  }
}

bool
hsk_dns_question_read(
  uint8_t **data,
  size_t *data_len,
  uint8_t *pd,
  size_t pd_len,
  hsk_dns_question_t *qs
) {
  if (!hsk_dns_alloc_name(data, data_len, pd, pd_len, &qs->name))
    goto fail;

  if (!read_u16be(data, data_len, &qs->type))
    goto fail;

  if (!read_u16be(data, data_len, &qs->class))
    goto fail;

  return true;

fail:
  if (qs->name) {
    free(qs->name);
    qs->name = NULL;
  }

  return false;
}

void
hsk_dns_rd_init(uint16_t type, void *rd) {
  if (rd == NULL)
    return;

  switch (type) {
    case HSK_DNS_SOA: {
      hsk_dns_soa_rd_t *r = (hsk_dns_soa_rd_t *)rd;
      r->ns = NULL;
      r->mbox = NULL;
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
      r->target = NULL;
      break;
    }
    case HSK_DNS_DNAME: {
      hsk_dns_dname_rd_t *r = (hsk_dns_dname_rd_t *)rd;
      r->target = NULL;
      break;
    }
    case HSK_DNS_NS: {
      hsk_dns_ns_rd_t *r = (hsk_dns_ns_rd_t *)rd;
      r->ns = NULL;
      break;
    }
    case HSK_DNS_MX: {
      hsk_dns_mx_rd_t *r = (hsk_dns_mx_rd_t *)rd;
      r->preference = 0;
      r->mx = NULL;
      break;
    }
    case HSK_DNS_PTR: {
      hsk_dns_ptr_rd_t *r = (hsk_dns_ptr_rd_t *)rd;
      r->ptr = NULL;
      break;
    }
    case HSK_DNS_SRV: {
      hsk_dns_srv_rd_t *r = (hsk_dns_srv_rd_t *)rd;
      r->priority = 0;
      r->weight = 0;
      r->port = 0;
      r->target = NULL;
      break;
    }
    case HSK_DNS_TXT: {
      hsk_dns_txt_rd_t *r = (hsk_dns_txt_rd_t *)rd;
      r->text = NULL;
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
      r->type = 0;
      r->fingerprint_len = 0;
      r->fingerprint = NULL;
      break;
    }
    case HSK_DNS_OPENPGPKEY: {
      hsk_dns_openpgpkey_rd_t *r = (hsk_dns_openpgpkey_rd_t *)rd;
      r->public_key_len = 0;
      r->public_key = NULL;
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

void *
hsk_dns_rd_alloc(uint16_t type) {
  void *rd;

  switch (type) {
    case HSK_DNS_SOA: {
      rd = (void *)malloc(sizeof(hsk_dns_soa_rd_t));
      break;
    }
    case HSK_DNS_A: {
      rd = (void *)malloc(sizeof(hsk_dns_a_rd_t));
      break;
    }
    case HSK_DNS_AAAA: {
      rd = (void *)malloc(sizeof(hsk_dns_aaaa_rd_t));
      break;
    }
    case HSK_DNS_CNAME: {
      rd = (void *)malloc(sizeof(hsk_dns_cname_rd_t));
      break;
    }
    case HSK_DNS_DNAME: {
      rd = (void *)malloc(sizeof(hsk_dns_dname_rd_t));
      break;
    }
    case HSK_DNS_NS: {
      rd = (void *)malloc(sizeof(hsk_dns_ns_rd_t));
      break;
    }
    case HSK_DNS_MX: {
      rd = (void *)malloc(sizeof(hsk_dns_mx_rd_t));
      break;
    }
    case HSK_DNS_PTR: {
      rd = (void *)malloc(sizeof(hsk_dns_ptr_rd_t));
      break;
    }
    case HSK_DNS_SRV: {
      rd = (void *)malloc(sizeof(hsk_dns_srv_rd_t));
      break;
    }
    case HSK_DNS_TXT: {
      rd = (void *)malloc(sizeof(hsk_dns_txt_rd_t));
      break;
    }
    case HSK_DNS_DS: {
      rd = (void *)malloc(sizeof(hsk_dns_ds_rd_t));
      break;
    }
    case HSK_DNS_TLSA: {
      rd = (void *)malloc(sizeof(hsk_dns_tlsa_rd_t));
      break;
    }
    case HSK_DNS_SSHFP: {
      rd = (void *)malloc(sizeof(hsk_dns_sshfp_rd_t));
      break;
    }
    case HSK_DNS_OPENPGPKEY: {
      rd = (void *)malloc(sizeof(hsk_dns_openpgpkey_rd_t));
      break;
    }
    default: {
      rd = (void *)malloc(sizeof(hsk_dns_unknown_rd_t));
      break;
    }
  }

  hsk_dns_rd_init(type, rd);

  return rd;
}

void
hsk_dns_rd_free(uint16_t type, void *rd) {
  if (rd == NULL)
    return;

  switch (type) {
    case HSK_DNS_SOA: {
      hsk_dns_soa_rd_t *r = (hsk_dns_soa_rd_t *)rd;
      if (r->ns)
        free(r->ns);
      if (r->mbox)
        free(r->mbox);
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
      if (r->target)
        free(r->target);
      break;
    }
    case HSK_DNS_DNAME: {
      hsk_dns_dname_rd_t *r = (hsk_dns_dname_rd_t *)rd;
      if (r->target)
        free(r->target);
      break;
    }
    case HSK_DNS_NS: {
      hsk_dns_ns_rd_t *r = (hsk_dns_ns_rd_t *)rd;
      if (r->ns)
        free(r->ns);
      break;
    }
    case HSK_DNS_MX: {
      hsk_dns_mx_rd_t *r = (hsk_dns_mx_rd_t *)rd;
      if (r->mx)
        free(r->mx);
      break;
    }
    case HSK_DNS_PTR: {
      hsk_dns_ptr_rd_t *r = (hsk_dns_ptr_rd_t *)rd;
      if (r->ptr)
        free(r->ptr);
      break;
    }
    case HSK_DNS_SRV: {
      hsk_dns_srv_rd_t *r = (hsk_dns_srv_rd_t *)rd;
      if (r->target)
        free(r->target);
      break;
    }
    case HSK_DNS_TXT: {
      hsk_dns_txt_rd_t *r = (hsk_dns_txt_rd_t *)rd;
      if (r->text)
        hsk_dns_text_free_list(r->text);
      break;
    }
    case HSK_DNS_DS: {
      hsk_dns_ds_rd_t *r = (hsk_dns_ds_rd_t *)rd;
      if (r->digest)
        free(r->digest);
      break;
    }
    case HSK_DNS_TLSA: {
      hsk_dns_tlsa_rd_t *r = (hsk_dns_tlsa_rd_t *)rd;
      if (r->certificate)
        free(r->certificate);
      break;
    }
    case HSK_DNS_SSHFP: {
      hsk_dns_sshfp_rd_t *r = (hsk_dns_sshfp_rd_t *)rd;
      if (r->fingerprint)
        free(r->fingerprint);
      break;
    }
    case HSK_DNS_OPENPGPKEY: {
      hsk_dns_openpgpkey_rd_t *r = (hsk_dns_openpgpkey_rd_t *)rd;
      if (r->public_key)
        free(r->public_key);
      break;
    }
    default: {
      hsk_dns_unknown_rd_t *r = (hsk_dns_unknown_rd_t *)rd;
      if (r->rd)
        free(r->rd);
      break;
    }
  }

  free(rd);
}

bool
hsk_dns_rd_read(
  uint8_t **data,
  size_t *data_len,
  uint8_t *pd,
  size_t pd_len,
  uint16_t type,
  void *rd
) {
  switch (type) {
    case HSK_DNS_SOA: {
      hsk_dns_soa_rd_t *r = (hsk_dns_soa_rd_t *)rd;

      if (!hsk_dns_alloc_name(data, data_len, pd, pd_len, &r->ns))
        goto fail_soa;

      if (!hsk_dns_alloc_name(data, data_len, pd, pd_len, &r->mbox))
        goto fail_soa;

      if (!read_u32be(data, data_len, &r->serial))
        goto fail_soa;

      if (!read_u32be(data, data_len, &r->refresh))
        goto fail_soa;

      if (!read_u32be(data, data_len, &r->retry))
        goto fail_soa;

      if (!read_u32be(data, data_len, &r->expire))
        goto fail_soa;

      if (!read_u32be(data, data_len, &r->minttl))
        goto fail_soa;

      break;

fail_soa:
      if (r->ns) {
        free(r->ns);
        r->ns = NULL;
      }

      if (r->mbox) {
        free(r->mbox);
        r->mbox = NULL;
      }

      return false;
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

      if (!hsk_dns_alloc_name(data, data_len, pd, pd_len, &r->target))
        return false;

      break;
    }
    case HSK_DNS_DNAME: {
      hsk_dns_dname_rd_t *r = (hsk_dns_dname_rd_t *)rd;

      if (!hsk_dns_alloc_name(data, data_len, pd, pd_len, &r->target))
        return false;

      break;
    }
    case HSK_DNS_NS: {
      hsk_dns_ns_rd_t *r = (hsk_dns_ns_rd_t *)rd;

      if (!hsk_dns_alloc_name(data, data_len, pd, pd_len, &r->ns))
        return false;

      break;
    }
    case HSK_DNS_MX: {
      hsk_dns_mx_rd_t *r = (hsk_dns_mx_rd_t *)rd;

      if (!read_u16be(data, data_len, &r->preference))
        return false;

      if (!hsk_dns_alloc_name(data, data_len, pd, pd_len, &r->mx))
        return false;

      break;
    }
    case HSK_DNS_PTR: {
      hsk_dns_ptr_rd_t *r = (hsk_dns_ptr_rd_t *)rd;

      if (!hsk_dns_alloc_name(data, data_len, pd, pd_len, &r->ptr))
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

      if (!hsk_dns_alloc_name(data, data_len, pd, pd_len, &r->target))
        return false;

      break;
    }
    case HSK_DNS_TXT: {
      hsk_dns_txt_rd_t *r = (hsk_dns_txt_rd_t *)rd;
      hsk_dns_text_t *parent = NULL;

      while (*data_len > 0) {
        hsk_dns_text_t *text = hsk_dns_text_alloc();

        if (text == NULL)
          goto fail_txt;

        if (!read_u8(data, data_len, &text->data_len))
          goto fail_txt;

        if (!alloc_bytes(data, data_len, &text->data, text->data_len))
          goto fail_txt;

        if (r->text == NULL)
          r->text = text;

        if (parent)
          parent->next = text;

        parent = text;
      }

      break;

fail_txt:
      if (r->text) {
        hsk_dns_text_free_list(r->text);
        r->text = NULL;
      }
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

      if (!read_u8(data, data_len, &r->type))
        return false;

      r->fingerprint_len = *data_len;

      if (!alloc_bytes(data, data_len, &r->fingerprint, *data_len))
        return false;

      break;
    }
    case HSK_DNS_OPENPGPKEY: {
      hsk_dns_openpgpkey_rd_t *r = (hsk_dns_openpgpkey_rd_t *)rd;

      r->public_key_len = *data_len;

      if (!alloc_bytes(data, data_len, &r->public_key, *data_len))
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
hsk_dns_record_read(
  uint8_t **data,
  size_t *data_len,
  uint8_t *pd,
  size_t pd_len,
  hsk_dns_record_t *rr
) {
  if (!hsk_dns_alloc_name(data, data_len, pd, pd_len, &rr->name))
    goto fail;

  if (!read_u16be(data, data_len, &rr->type))
    goto fail;

  if (!read_u16be(data, data_len, &rr->class))
    goto fail;

  if (!read_u32be(data, data_len, &rr->ttl))
    goto fail;

  uint16_t len;

  if (!read_u16be(data, data_len, &len))
    goto fail;

  if (*data_len < len)
    goto fail;

  rr->rd = hsk_dns_rd_alloc(rr->type);

  if (rr->rd == NULL)
    goto fail;

  uint8_t *rd = *data;
  size_t rdlen = (size_t)len;

  if (!hsk_dns_rd_read(&rd, &rdlen, pd, pd_len, rr->type, rr->rd))
    goto fail;

  *data += len;
  *data_len -= len;

  return true;

fail:
  if (rr->name) {
    free(rr->name);
    rr->name = NULL;
  }

  if (rr->rd) {
    free(rr->rd);
    rr->rd = NULL;
  }

  return false;
}

bool
hsk_dns_message_read(uint8_t **data, size_t *data_len, hsk_dns_message_t *msg) {
  uint8_t *pd = *data;
  size_t pd_len = *data_len;

  if (!read_u16be(data, data_len, &msg->id))
    return false;

  if (!read_u16be(data, data_len, &msg->flags))
    return false;

  if (!read_u16be(data, data_len, &msg->qdcount))
    return false;

  if (!read_u16be(data, data_len, &msg->ancount))
    return false;

  if (!read_u16be(data, data_len, &msg->nscount))
    return false;

  if (!read_u16be(data, data_len, &msg->arcount))
    return false;

  uint32_t i;

  {
    hsk_dns_question_t *parent = NULL;
    for (i = 0; i < msg->qdcount; i++) {
      if (*data_len == 0)
        break;

      hsk_dns_question_t *qs = hsk_dns_question_alloc();

      if (qs == NULL)
        goto fail;

      if (!hsk_dns_question_read(data, data_len, pd, pd_len, qs))
        goto fail;

      if (msg->question == NULL)
        msg->question = qs;

      if (parent)
        parent->next = qs;

      parent = qs;
    }
  }

  hsk_dns_record_t *parent = NULL;
  for (i = 0; i < msg->ancount; i++) {
    if (msg->flags & HSK_DNS_TC) {
      if (*data_len == 0)
        break;
    }

    hsk_dns_record_t *rr = hsk_dns_record_alloc();

    if (rr == NULL)
      goto fail;

    if (!hsk_dns_record_read(data, data_len, pd, pd_len, rr))
      goto fail;

    if (msg->answer == NULL)
      msg->answer = rr;

    if (parent)
      parent->next = rr;

    parent = rr;
  }

  parent = NULL;
  for (i = 0; i < msg->nscount; i++) {
    if (msg->flags & HSK_DNS_TC) {
      if (*data_len == 0)
        break;
    }

    hsk_dns_record_t *rr = hsk_dns_record_alloc();

    if (rr == NULL)
      goto fail;

    if (!hsk_dns_record_read(data, data_len, pd, pd_len, rr))
      goto fail;

    if (msg->authority == NULL)
      msg->authority = rr;

    if (parent)
      parent->next = rr;

    parent = rr;
  }

  parent = NULL;
  for (i = 0; i < msg->arcount; i++) {
    if (*data_len == 0)
      break;

    hsk_dns_record_t *rr = hsk_dns_record_alloc();

    if (rr == NULL)
      goto fail;

    if (!hsk_dns_record_read(data, data_len, pd, pd_len, rr))
      goto fail;

    if (msg->additional == NULL)
      msg->additional = rr;

    if (parent)
      parent->next = rr;

    parent = rr;
  }

  return true;

fail:
  hsk_dns_question_free_list(msg->question);
  hsk_dns_record_free_list(msg->answer);
  hsk_dns_record_free_list(msg->authority);
  hsk_dns_record_free_list(msg->additional);
  hsk_dns_message_init(msg);
  return false;
}

bool
hsk_dns_message_decode(uint8_t *data, size_t data_len, hsk_dns_message_t **msg) {
  hsk_dns_message_t *m = hsk_dns_message_alloc();

  if (m == NULL)
    return false;

  if (!hsk_dns_message_read(&data, &data_len, m))
    return false;

  *msg = m;

  return true;
}

hsk_dns_record_t *
hsk_dns_get_record(hsk_dns_record_t *rr, char *target, uint8_t type) {
  hsk_dns_record_t *c;

  char *glue = target;

  for (c = rr; c; c = c->next) {
    if (!target) {
      if (c->type == type || type == HSK_DNS_ANY)
        return c;
      continue;
    }

    if (c->type == HSK_DNS_CNAME) {
      if (hsk_dns_name_cmp(c->name, glue) == 0) {
        if (type == HSK_DNS_CNAME || type == HSK_DNS_ANY)
          return c;

        glue = ((hsk_dns_cname_rd_t *)c->rd)->target;
      }
      continue;
    }

    if (c->type == type || type == HSK_DNS_ANY) {
      if (hsk_dns_name_cmp(c->name, glue) == 0)
        return c;
      continue;
    }
  }

  return NULL;
}

void
hsk_dns_iterator_init(
  hsk_dns_iterator_t *it,
  hsk_dns_record_t *section,
  char *target,
  uint8_t type
) {
  it->target = target;
  it->type = type;
  it->current = section;
}

hsk_dns_record_t *
hsk_dns_iterator_next(hsk_dns_iterator_t *it) {
  if (it->current == NULL)
    return NULL;

  hsk_dns_record_t *c = hsk_dns_get_record(it->current, it->target, it->type);

  if (c == NULL) {
    it->current = NULL;
    return NULL;
  }

  if (it->target)
    it->target = c->name;

  it->current = c->next;

  return c;
}
