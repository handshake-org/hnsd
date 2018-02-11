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
#include "msg.h"

int32_t
dns_name_cmp(char *a, char *b) {
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
dns_parse_name(
  uint8_t **data_,
  size_t *data_len_,
  dns_message_t *msg,
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
                if (name)
                  name[noff] = b;
                noff += 1;
              }
              break;
            }
          }

          if (noff >= max)
            return -1;
        }

        if (name)
          name[noff] = '.';

        noff += 1;
        off += c;

        break;
      }

      case 0xc0: {
        if (!msg)
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

        data = msg->pd;
        data_len = msg->pd_len;

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
dns_read_name(
  uint8_t **data,
  size_t *data_len,
  dns_message_t *msg,
  char *name
) {
  return dns_parse_name(data, data_len, msg, name) != -1;
}

int32_t
dns_size_name(uint8_t *data, size_t data_len, dns_message_t *msg) {
  return dns_parse_name(&data, &data_len, msg, NULL);
}

bool
dns_alloc_name(
  uint8_t **data,
  size_t *data_len,
  dns_message_t *msg,
  char **name
) {
  int32_t size = dns_size_name(*data, *data_len, msg);

  if (size == -1)
    return false;

  *name = malloc(size + 1);

  if (*name == NULL)
    return false;

  assert(dns_read_name(data, data_len, msg, *name));

  return true;
}

void
dns_message_init(dns_message_t *msg) {
  if (msg == NULL)
    return;

  msg->pd_len = 0;
  msg->pd = NULL;
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
dns_question_init(dns_question_t *qs) {
  if (qs == NULL)
    return;

  qs->name = NULL;
  qs->type = 0;
  qs->class = 0;
  qs->next = NULL;
}

void
dns_record_init(dns_record_t *rr) {
  if (rr == NULL)
    return;

  rr->parent = NULL;
  rr->name = NULL;
  rr->type = 0;
  rr->class = 0;
  rr->ttl = 0;
  rr->rd_len = 0;
  rr->rd = NULL;
  rr->next = NULL;
}

void
dns_text_init(dns_text_t *text) {
  if (text == NULL)
    return;

  text->data_len = 0;
  text->data = NULL;
  text->next = NULL;
}

dns_message_t *
dns_message_alloc(void) {
  dns_message_t *msg = malloc(sizeof(dns_message_t));
  dns_message_init(msg);
  return msg;
}

dns_question_t *
dns_question_alloc(void) {
  dns_question_t *qs = malloc(sizeof(dns_question_t));
  dns_question_init(qs);
  return qs;
}

dns_record_t *
dns_record_alloc(void) {
  dns_record_t *rr = malloc(sizeof(dns_record_t));
  dns_record_init(rr);
  return rr;
}

dns_text_t *
dns_text_alloc(void) {
  dns_text_t *text = malloc(sizeof(dns_text_t));
  dns_text_init(text);
  return text;
}

void
dns_question_free(dns_question_t *qs) {
  if (qs == NULL)
    return;

  if (qs->name)
    free(qs->name);

  free(qs);
}

void
dns_record_free(dns_record_t *rr) {
  if (rr == NULL)
    return;

  if (rr->name)
    free(rr->name);

  if (!rr->parent && rr->rd)
    free(rr->rd);

  free(rr);
}

dns_record_t *
dns_record_clone(dns_record_t *rr) {
  if (rr == NULL)
    return NULL;

  dns_record_t *r = dns_record_alloc();

  if (r == NULL)
    return NULL;

  r->parent = rr->parent;
  r->type = rr->type;
  r->class = rr->class;
  r->ttl = rr->ttl;
  r->rd_len = rr->rd_len;

  r->name = strdup(rr->name);

  if (r->name == NULL)
    goto fail;

  if (rr->parent) {
    r->rd = rr->rd;
  } else {
    r->rd = malloc(rr->rd_len);
    if (r->rd == NULL)
      goto fail;
    memcpy(r->rd, rr->rd, rr->rd_len);
  }

  return r;
fail:
  dns_record_free(r);
  return NULL;
}

void
dns_question_free_list(dns_question_t *qs) {
  dns_question_t *c, *n;
  for (c = qs; c; c = n) {
    n = c->next;
    dns_question_free(c);
  }
}

void
dns_record_free_list(dns_record_t *rr) {
  dns_record_t *c, *n;
  for (c = rr; c; c = n) {
    n = c->next;
    dns_record_free(c);
  }
}

void
dns_message_free(dns_message_t *msg) {
  if (msg == NULL)
    return;

  if (msg->pd)
    free(msg->pd);

  dns_question_free_list(msg->question);
  dns_record_free_list(msg->answer);
  dns_record_free_list(msg->authority);
  dns_record_free_list(msg->additional);
  free(msg);
}

void
dns_text_free(dns_text_t *text) {
  if (text == NULL)
    return;

  if (text->data)
    free(text->data);

  free(text);
}

void
dns_text_free_list(dns_text_t *text) {
  dns_text_t *c, *n;
  for (c = text; c; c = n) {
    n = c->next;
    dns_text_free(c);
  }
}

bool
dns_read_question(
  uint8_t **data,
  size_t *data_len,
  dns_message_t *msg,
  dns_question_t *qs
) {
  if (!dns_alloc_name(data, data_len, msg, &qs->name))
    return false;

  if (!read_u16be(data, data_len, &qs->type))
    return false;

  if (!read_u16be(data, data_len, &qs->class))
    return false;

  return true;
}

bool
dns_read_record(
  uint8_t **data,
  size_t *data_len,
  dns_message_t *msg,
  dns_record_t *rr
) {
  if (!dns_alloc_name(data, data_len, msg, &rr->name))
    return false;

  if (!read_u16be(data, data_len, &rr->type))
    return false;

  if (!read_u16be(data, data_len, &rr->class))
    return false;

  if (!read_u32be(data, data_len, &rr->ttl))
    return false;

  if (!read_u16be(data, data_len, &rr->rd_len))
    return false;

  if (msg) {
    rr->parent = msg;
    if (!slice_bytes(data, data_len, &rr->rd, rr->rd_len))
      return false;
  } else {
    if (!alloc_bytes(data, data_len, &rr->rd, rr->rd_len))
      return false;
  }

  return true;
}

bool
dns_read_message(uint8_t **data, size_t *data_len, dns_message_t *msg) {
  msg->pd = *data;
  msg->pd_len = *data_len;

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
    dns_question_t *parent = NULL;
    for (i = 0; i < msg->qdcount; i++) {
      if (*data_len == 0)
        break;

      dns_question_t *qs = dns_question_alloc();

      if (qs == NULL)
        goto fail;

      if (!dns_read_question(data, data_len, msg, qs))
        goto fail;

      if (msg->question == NULL)
        msg->question = qs;

      if (parent)
        parent->next = qs;

      parent = qs;
    }
  }

  dns_record_t *parent = NULL;
  for (i = 0; i < msg->ancount; i++) {
    if (msg->flags & DNS_TC) {
      if (*data_len == 0)
        break;
    }

    dns_record_t *rr = dns_record_alloc();

    if (rr == NULL)
      goto fail;

    if (!dns_read_record(data, data_len, msg, rr))
      goto fail;

    if (msg->answer == NULL)
      msg->answer = rr;

    if (parent)
      parent->next = rr;

    parent = rr;
  }

  parent = NULL;
  for (i = 0; i < msg->nscount; i++) {
    if (msg->flags & DNS_TC) {
      if (*data_len == 0)
        break;
    }

    dns_record_t *rr = dns_record_alloc();

    if (rr == NULL)
      goto fail;

    if (!dns_read_record(data, data_len, msg, rr))
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

    dns_record_t *rr = dns_record_alloc();

    if (rr == NULL)
      goto fail;

    if (!dns_read_record(data, data_len, msg, rr))
      goto fail;

    if (msg->additional == NULL)
      msg->additional = rr;

    if (parent)
      parent->next = rr;

    parent = rr;
  }

  return true;

fail:
  dns_question_free_list(msg->question);
  dns_record_free_list(msg->answer);
  dns_record_free_list(msg->authority);
  dns_record_free_list(msg->additional);
  dns_message_init(msg);
  return false;
}

bool
dns_decode_message(uint8_t *data, size_t data_len, dns_message_t **msg) {
  *msg = NULL;

  dns_message_t *m = dns_message_alloc();

  if (m == NULL)
    return false;

  if (!dns_read_message(&data, &data_len, m))
    return false;

  *msg = m;

  return true;
}

bool
dns_read_a_record(dns_record_t *rr, uint8_t *ipv4) {
  if (rr->type != DNS_A)
    return false;

  uint8_t *rd = rr->rd;
  size_t rd_len = rr->rd_len;

  return read_bytes(&rd, &rd_len, ipv4, 4);
}

bool
dns_alloc_a_record(dns_record_t *rr, uint8_t **ipv4) {
  if (rr->type != DNS_A)
    return false;

  uint8_t *rd = rr->rd;
  size_t rd_len = rr->rd_len;

  return alloc_bytes(&rd, &rd_len, ipv4, 4);
}

bool
dns_read_aaaa_record(dns_record_t *rr, uint8_t *ipv6) {
  if (rr->type != DNS_AAAA)
    return false;

  uint8_t *rd = rr->rd;
  size_t rd_len = rr->rd_len;

  return read_bytes(&rd, &rd_len, ipv6, 16);
}

bool
dns_alloc_aaaa_record(dns_record_t *rr, uint8_t **ipv6) {
  if (rr->type != DNS_AAAA)
    return false;

  uint8_t *rd = rr->rd;
  size_t rd_len = rr->rd_len;

  return alloc_bytes(&rd, &rd_len, ipv6, 16);
}

bool
dns_read_cname_record(dns_record_t *rr, char *name) {
  if (rr->type != DNS_CNAME)
    return false;

  uint8_t *rd = rr->rd;
  size_t rd_len = rr->rd_len;

  return dns_read_name(&rd, &rd_len, rr->parent, name);
}

bool
dns_alloc_cname_record(dns_record_t *rr, char **name) {
  if (rr->type != DNS_CNAME)
    return false;

  uint8_t *rd = rr->rd;
  size_t rd_len = rr->rd_len;

  return dns_alloc_name(&rd, &rd_len, rr->parent, name);
}

bool
dns_read_ns_record(dns_record_t *rr, char **name) {
  if (rr->type != DNS_NS)
    return false;

  uint8_t *rd = rr->rd;
  size_t rd_len = rr->rd_len;

  return dns_alloc_name(&rd, &rd_len, rr->parent, name);
}

bool
dns_read_txt_record(dns_record_t *rr, dns_text_t **text) {
  if (rr->type != DNS_TXT)
    return false;

  *text = NULL;

  uint8_t *rd = rr->rd;
  size_t rd_len = rr->rd_len;

  dns_text_t *parent = NULL;

  while (rd_len > 0) {
    dns_text_t *t = dns_text_alloc();

    if (t == NULL)
      goto fail;

    if (!read_u8(&rd, &rd_len, &t->data_len))
      goto fail;

    if (!alloc_bytes(&rd, &rd_len, &t->data, t->data_len))
      goto fail;

    if (*text == NULL)
      *text = t;

    if (parent)
      parent->next = t;

    parent = t;
  }

  return true;

fail:
  dns_text_free_list(*text);
  *text = NULL;
  return false;
}

dns_record_t *
dns_get_record(dns_record_t *rr, char *target, uint8_t type) {
  dns_record_t *c;

  char glue[1021];

  if (target)
    strcpy(glue, target);

  for (c = rr; c; c = c->next) {
    if (!target) {
      if (c->type == type)
        return c;
      continue;
    }

    if (c->type == DNS_CNAME) {
      if (dns_name_cmp(c->name, glue) == 0) {
        if (type == DNS_CNAME)
          return c;

        if (!dns_read_cname_record(c, glue))
          return NULL;
      }
      continue;
    }

    if (c->type == type || type == DNS_ANY) {
      if (dns_name_cmp(c->name, glue) == 0)
        return c;
      continue;
    }
  }

  return NULL;
}

dns_record_t *
dns_get_records(dns_record_t *rr, char *target, uint8_t type) {
  dns_record_t *head = NULL;
  dns_record_t *parent = NULL;
  dns_record_t *c = rr;

  while (c) {
    c = dns_get_record(c, target, type);

    if (c == NULL)
      break;

    dns_record_t *r = dns_record_clone(c);

    if (r == NULL)
      goto fail;

    if (head == NULL)
      head = r;

    if (parent)
      parent->next = r;

    parent = r;

    target = c->name;
    c = c->next;
  }

  return head;

fail:
  dns_record_free(head);
  return NULL;
}
