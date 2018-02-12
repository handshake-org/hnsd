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

#include "cares/ares.h"
#include "cares/ares_dns.h"
#include "cares/nameser.h"

#include "b64.h"
#include "msg.c"
#include "hsk-hash.h"
#include "hsk-error.h"
#include "hsk-proof.h"
#include "hsk-name.h"
#include "hsk-header.h"
#include "hsk-resource.h"

typedef struct {
  int32_t status;
  int32_t timeouts;
  struct hostent *host;
} _hsk_hostent_ret_t;

typedef struct {
  int32_t status;
  int32_t timeouts;
  dns_message_t *msg;
} hsk__query_ret_t;

typedef struct {
  char *host;
  int32_t port;
} _hsk_ns_t;

static void
cb_after_query(
  void *arg,
  int32_t status,
  int32_t timeouts,
  uint8_t *abuf,
  int32_t alen
);

static const _hsk_ns_t nameservers[] = {
  { .host = "127.0.0.1", .port = 53 },
  { .host = NULL, .port = 0 }
};

static struct ares_addr_port_node *gn = NULL;

bool
hsk_is_hskn(char *name, size_t len) {
  if (name == NULL)
    return false;

  char *s = name;

  if (len == 1) {
    if (s[0] == 'h')
      return true;
    if (s[0] == 'i')
      return true;
    return false;
  }

  if (s[len - 1] == '.')
    len -= 1;

  if (s[len - 1] != 'h' && s[len - 1] != 'i')
    return false;

  len -= 1;

  if (len > 0 && s[len - 1] != '.')
    return false;

  return true;
}

bool
hsk_is_hsk(char *name) {
  if (name == NULL)
    return false;

  return hsk_is_hskn(name, strlen(name));
}

bool
hsk_is_sld(char *name) {
  if (name == NULL)
    return false;

  bool dot = false;
  size_t l = 0;
  char *s;

  for (s = (char *)name; *s; s++, l++) {
    if (*s == '.') {
      if (l == 0)
        return false;

      if (*(s - 1) == '.')
        return false;

      if (*(s + 1)) {
        if (dot)
          return false;
        dot = true;
      }
    }
  }

  if (!hsk_is_hskn(name, l))
    return false;

  return true;
}

char *
hsk_to_tld(char *name) {
  if (!hsk_is_sld(name))
    return NULL;

  size_t len = strlen(name);
  assert(len >= 3);

  if (name[len - 1] == '.')
    len -= 1;

  assert(len >= 3);
  assert(name[--len] == 'h');
  assert(name[--len] == '.');

  char *s = malloc(len + 1);

  if (s == NULL)
    return NULL;

  memcpy(s, name, len);
  s[len] = '\0';

  return s;
}

static struct hostent *
copy_hostent(struct hostent *host) {
  if (host == NULL)
    return NULL;

  size_t alias_len = 0;
  char **alias;

  for (alias = host->h_aliases; *alias; alias++)
    alias_len += 1;

  char **aliases = malloc((alias_len + 1) * sizeof(char *));

  if (aliases == NULL)
    return NULL;

  alias_len = 0;

  for (alias = host->h_aliases; *alias; alias++) {
    char *a = strdup(*alias);
    if (a == NULL)
      return NULL;
    aliases[alias_len++] = a;
  }

  aliases[alias_len] = NULL;

  size_t addr_len = 0;
  char **addr;

  for (addr = host->h_addr_list; *addr; addr++)
    addr_len += 1;

  char **addr_list = malloc((addr_len + 1) * sizeof(struct sockaddr *));

  if (addr_list == NULL)
    return NULL;

  char *addrs = malloc(addr_len * sizeof(struct sockaddr));

  if (addrs == NULL)
    return NULL;

  addr_len = 0;
  for (addr = host->h_addr_list; *addr; addr++) {
    memcpy(addrs, *addr, sizeof(struct sockaddr));
    addr_list[addr_len++] = addrs;
    addrs += sizeof(struct sockaddr);
  }
  addr_list[addr_len] = NULL;

  struct hostent *h = malloc(sizeof(struct hostent));

  if (h == NULL)
    return NULL;

  h->h_name = strdup(host->h_name);

  if (h->h_name == NULL)
    return NULL;

  h->h_aliases = aliases;
  h->h_addrtype = host->h_addrtype;
  h->h_length = addr_len;
  h->h_addr_list = addr_list;

  return h;
}

static int32_t
hsk__init_servers(struct ares_addr_port_node **n) {
  if (gn != NULL) {
    *n = gn;
    return HSK_SUCCESS;
  }

  *n = NULL;

  struct ares_addr_port_node *pn = NULL;
  const _hsk_ns_t *ns;

  for (ns = nameservers; ns->port != 0; ns++) {
    struct ares_addr_port_node *cn = malloc(sizeof(struct ares_addr_port_node));

    if (cn == NULL)
      return HSK_ENOMEM;

    if (ares_inet_pton(AF_INET, ns->host, &cn->addr.addr4) == 1) {
      cn->family = AF_INET;
    } else if (ares_inet_pton(AF_INET6, ns->host, &cn->addr.addr6) == 1) {
      cn->family = AF_INET6;
    } else {
      return HSK_EBADSTR;
    }

    cn->udp_port = ns->port;
    cn->tcp_port = ns->port;
    cn->next = NULL;

    if (pn)
      pn->next = cn;

    pn = cn;
  }

  *n = pn;
  gn = pn;

  return HSK_SUCCESS;
}

static int32_t
hsk__query(char *name, int32_t type, dns_message_t **msg) {
  int32_t rc;

  if (msg == NULL)
    return HSK_EBADSTR;

  *msg = NULL;

  if (name == NULL)
    return HSK_EBADSTR;

  rc = ares_library_init(ARES_LIB_INIT_ALL);

  if (rc != ARES_SUCCESS)
    return rc;

  ares_channel channel;
  rc = ares_init(&channel);

  if (rc != ARES_SUCCESS)
    return rc;

  struct ares_options options;
  options.flags = ARES_FLAG_EDNS;
  rc = ares_init_options(&channel, &options, ARES_OPT_FLAGS);

  if (rc != ARES_SUCCESS) {
    ares_destroy(channel);
    return rc;
  }

  struct ares_addr_port_node *n;

  rc = hsk__init_servers(&n);

  if (rc != HSK_SUCCESS) {
    ares_destroy(channel);
    return rc;
  }

  rc = ares_set_servers_ports(channel, n);

  if (rc != ARES_SUCCESS) {
    ares_destroy(channel);
    return rc;
  }

  hsk__query_ret_t ret;
  ares_query(channel, name, DNS_INET, type, cb_after_query, &ret);

  fd_set readers, writers;
  struct timeval *tvp, tv;
  int32_t nfds;

  for (;;) {
    FD_ZERO(&readers);
    FD_ZERO(&writers);

    nfds = ares_fds(channel, &readers, &writers);

    if (nfds == 0)
      break;

    tvp = ares_timeout(channel, NULL, &tv);
    select(nfds, &readers, &writers, NULL, tvp);
    ares_process(channel, &readers, &writers);
  }

  ares_destroy(channel);

  if (ret.status != ARES_SUCCESS) {
    if (ret.msg != NULL)
      dns_message_free(ret.msg);
    return ret.status;
  }

  if (ret.msg == NULL)
    return HSK_ENODATA;

  rc = hsk_verify_dns(ret.msg, name, type);

  if (rc != HSK_SUCCESS)  {
    dns_message_free(ret.msg);
    return rc;
  }

  *msg = ret.msg;

  return ret.status;
}

static void
cb_after_query(
  void *arg,
  int32_t status,
  int32_t timeouts,
  unsigned char *abuf,
  int32_t alen
) {
  hsk__query_ret_t *ret = (hsk__query_ret_t *)arg;

  ret->status = status;
  ret->timeouts = timeouts;
  ret->msg = NULL;

  if (abuf) {
    uint8_t *data = malloc(alen * sizeof(char));

    if (data == NULL) {
      ret->status = HSK_ENOMEM;
      return;
    }

    memcpy(data, abuf, alen);

    if (!dns_decode_message(data, alen, &ret->msg)) {
      ret->status = HSK_ENOMEM;
      return;
    }
  }
}

static struct hostent *
parse_addr_records(dns_message_t *msg, char *target, uint8_t type) {
  assert(type == DNS_A || type == DNS_AAAA);

  dns_record_t *section = dns_get_records(msg->answer, target, type);
  struct hostent *host = NULL;

  if (section == NULL)
    goto fail;

  host = malloc(sizeof(struct hostent));

  if (host == NULL)
    goto fail;

  host->h_name = NULL;
  host->h_aliases = NULL;
  host->h_addrtype = type == DNS_A ? AF_INET : AF_INET6;
  host->h_length = 0;
  host->h_addr_list = NULL;

  dns_record_t *c;

  int32_t len = 0;
  for (c = section; c; c = c->next) {
    if (!host->h_name) {
      host->h_name = strdup(c->name);
      if (!host->h_name)
        goto fail;
    }
    len += 1;
  }

  host->h_aliases = (char **)malloc(1);

  if (!host->h_aliases)
    goto fail;

  host->h_aliases[0] = NULL;

  host->h_addr_list = (char **)malloc((len + 1) * sizeof(struct sockaddr *));

  if (!host->h_addr_list)
    goto fail;

  for (c = section; c; c = c->next) {
    uint8_t *sa = (uint8_t *)malloc(sizeof(struct sockaddr));

    if (sa == NULL)
      goto fail;

    if (type == DNS_A) {
      if (!dns_read_a_record(c, sa))
        goto fail;
    } else {
      if (!dns_read_aaaa_record(c, sa))
        goto fail;
    }

    host->h_addr_list[host->h_length] = (char *)sa;
    host->h_length += 1;
  }

  host->h_addr_list[host->h_length] = NULL;

  dns_record_free_list(section);

  return host;

fail:
  if (section)
    dns_record_free_list(section);

  if (host) {
    if (host->h_name)
      free(host->h_name);
    if (host->h_aliases)
      free(host->h_aliases);
    if (host->h_addr_list) {
      while (host->h_length--)
        free(host->h_addr_list[host->h_length]);
      free(host->h_addr_list);
    }
    free(host);
  }

  return NULL;
}

static int32_t
hsk__gethostbyname(char *name, int32_t af, struct hostent **host) {
  int32_t rc;

  if (host == NULL)
    return HSK_EBADSTR;

  *host = NULL;

  if (name == NULL)
    return HSK_EBADSTR;

  int32_t type;

  switch (af) {
    case AF_UNSPEC:
    case AF_INET:
      type = DNS_A;
      break;
    case AF_INET6:
      type = DNS_AAAA;
      break;
    default:
      return HSK_EBADSTR;
  }

  dns_message_t *msg;
  rc = hsk__query(name, type, &msg);

  if (rc != HSK_SUCCESS)
    return rc;

  *host = parse_addr_records(msg, (char *)name, type);

  if (*host == NULL) {
    dns_message_free(msg);
    return HSK_ENOMEM;
  }

  dns_message_free(msg);

  return HSK_SUCCESS;
}

static dns_text_t *
parse_txt_records(dns_record_t *section, char *target, char *prefix) {
  dns_record_t *slice = dns_get_records(section, target, DNS_TXT);

  if (slice == NULL)
    return NULL;

  size_t slen = strlen(prefix);
  dns_record_t *c;

  for (c = slice; c; c = c->next) {
    dns_text_t *text = NULL;

    if (!dns_read_txt_record(c, &text)) {
      dns_record_free_list(slice);
      return NULL;
    }

    if (!text)
      continue;

    if (!text->next) {
      dns_text_free_list(text);
      continue;
    }

    if (text->data_len != slen) {
      dns_text_free_list(text);
      continue;
    }

    if (memcmp(text->data, prefix, slen) != 0) {
      dns_text_free_list(text);
      continue;
    }

    dns_text_t *n = text->next;
    dns_text_free(text);
    dns_record_free_list(slice);

    return n;
  }

  dns_record_free_list(slice);

  return NULL;
}

static bool
parse_raw_record(
  dns_record_t *section,
  char *target,
  char *prefix,
  uint8_t **out,
  size_t *outlen
) {
  dns_text_t *txt = parse_txt_records(section, target, prefix);

  if (txt == NULL)
    return false;

  size_t size = 0;
  dns_text_t *c;

  for (c = txt; c; c = c->next)
    size += c->data_len;

  if (size > 10240) {
    dns_text_free_list(txt);
    return false;
  }

  char *b64 = malloc(size + 1);

  if (b64 == NULL) {
    dns_text_free_list(txt);
    return false;
  }

  char *s = b64;

  for (c = txt; c; c = c->next) {
    memcpy(s, c->data, c->data_len);
    s += c->data_len;
  }

  *s = '\0';

  dns_text_free_list(txt);

  *out = b64_decode(b64, size, outlen);

  if (*out == NULL)
    return false;

  return true;
}

int32_t
hsk_parse_proof(dns_record_t *section, char *name, hsk_proof_t **proof) {
  uint8_t *b64;
  size_t b64_len;

  if (!parse_raw_record(section, name, "hsk:proof", &b64, &b64_len))
    return HSK_ENOMEM;

  uint8_t *data = b64;
  size_t data_len = b64_len;

  hsk_proof_t *p = hsk_proof_alloc();

  if (p == NULL)
    goto fail;

  if (!read_bytes(&data, &data_len, p->block_hash, 32))
    goto fail;

  size_t count;

  if (!read_varsize(&data, &data_len, &count))
    goto fail;

  hsk_raw_node_t *parent = NULL;

  int32_t i;
  for (i = 0; i < count; i++) {
    hsk_raw_node_t *node = hsk_raw_node_alloc();

    if (node == NULL)
      goto fail;

    if (!alloc_varbytes(&data, &data_len, &node->data, &node->data_len))
      goto fail;

    if (p->nodes == NULL)
      p->nodes = node;

    if (parent)
      parent->next = node;

    parent = node;
  }

  if (data_len > 0) {
    if (!alloc_varbytes(&data, &data_len, &p->data, &p->data_len))
      goto fail;
  }

  free(b64);

  *proof = p;

  return HSK_SUCCESS;

fail:
  if (b64)
    free(b64);

  if (p)
    hsk_proof_free(p);

  return HSK_ENOMEM;
}

int32_t
hsk_parse_header(dns_record_t *section, char *name, hsk_header_t *hdr) {
  uint8_t *data;
  size_t data_len;

  if (!parse_raw_record(section, name, "hsk:header", &data, &data_len))
    return HSK_ENOMEM;

  if (!hsk_decode_header(data, data_len, hdr)) {
    free(data);
    return HSK_ENOMEM;
  }

  free(data);

  return HSK_SUCCESS;
}

int32_t
hsk_get_proof(char *name, hsk_proof_t **proof) {
  int32_t rc;

  if (proof == NULL)
    return HSK_EBADSTR;

  *proof = NULL;

  if (!hsk_is_sld(name))
    return HSK_EBADSTR;

  dns_message_t *msg;
  rc = hsk__query(name, DNS_TXT, &msg);

  if (rc != HSK_SUCCESS)
    return rc;

  rc = hsk_parse_proof(msg->answer, name, proof);

  if (rc != HSK_SUCCESS) {
    dns_message_free(msg);
    return rc;
  }

  dns_message_free(msg);

  return HSK_SUCCESS;
}

int32_t
hsk_verify_dns(dns_message_t *msg, char *name, int32_t type) {
  int32_t rc = HSK_SUCCESS;
  hsk_proof_t *proof = NULL;
  char *tld = NULL;
  uint8_t *dhash = NULL;
  hsk_resource_t *res = NULL;
  dns_record_t *section = NULL;

  if (!hsk_is_sld(name))
    goto cleanup;

  dns_record_t *proof_section = msg->additional;

  if (type == DNS_TXT)
    proof_section = msg->answer;

  rc = hsk_parse_proof(proof_section, name, &proof);

  if (rc != HSK_SUCCESS)
    goto cleanup;

  hsk_header_t hdr;
  rc = hsk_parse_header(proof_section, name, &hdr);

  if (rc != HSK_SUCCESS)
    goto cleanup;

  uint8_t hash[32];
  hsk_hash_header(&hdr, hash);

  if (memcmp(proof->block_hash, hash, 32) != 0) {
    rc = HSK_EHASHMISMATCH;
    goto cleanup;
  }

  rc = hsk_verify_pow(&hdr);

  if (rc != HSK_SUCCESS)
    goto cleanup;

  tld = hsk_to_tld(name);

  if (tld == NULL) {
    rc = HSK_ENOMEM;
    goto cleanup;
  }

  size_t dhash_len = 0;

  rc = hsk_verify_name(hdr.trie_root, tld, proof->nodes, &dhash, &dhash_len);

  if (rc != HSK_SUCCESS)
    goto cleanup;

  if (!dhash) {
    if (proof->data) {
      rc = HSK_ERECORDMISMATCH;
      goto cleanup;
    }

    if (msg->nscount != 1) {
      rc = HSK_ERECORDMISMATCH;
      goto cleanup;
    }

    if (msg->authority->type != DNS_SOA) {
      rc = HSK_ERECORDMISMATCH;
      goto cleanup;
    }

    if (type == DNS_TXT) {
      if (msg->ancount != 2) {
        rc = HSK_ERECORDMISMATCH;
        goto cleanup;
      }
      if (msg->arcount != 0) {
        rc = HSK_ERECORDMISMATCH;
        goto cleanup;
      }
      if (msg->answer->type != DNS_TXT
          || msg->answer->next->type != DNS_TXT) {
        rc = HSK_ERECORDMISMATCH;
        goto cleanup;
      }
    } else {
      if (msg->ancount != 0) {
        rc = HSK_ERECORDMISMATCH;
        goto cleanup;
      }
      if (msg->arcount != 2) {
        rc = HSK_ERECORDMISMATCH;
        goto cleanup;
      }
      if (msg->additional->type != DNS_TXT
          || msg->additional->next->type != DNS_TXT) {
        rc = HSK_ERECORDMISMATCH;
        goto cleanup;
      }
    }

    goto cleanup;
  }

  if (dhash_len != 32) {
    rc = HSK_EHASHMISMATCH;
    goto cleanup;
  }

  hsk_blake2b(proof->data, proof->data_len, hash);

  if (memcmp(hash, dhash, 32) != 0) {
    rc = HSK_EHASHMISMATCH;
    goto cleanup;
  }

  if (!proof->data) {
    rc = HSK_ERECORDMISMATCH;
    goto cleanup;
  }

  if (!hsk_decode_resource(proof->data, proof->data_len, &res)) {
    rc = HSK_EENCODING;
    goto cleanup;
  }

  if (type != DNS_A && type != DNS_AAAA)
    goto cleanup;

  hsk_host_record_t *canonical =
    (hsk_host_record_t *)hsk_resource_get(res, HSK_CANONICAL);

  // Verify glue.
  if (canonical) {
    dns_record_t *cname = msg->answer;

    if (!cname || cname->type != DNS_CNAME) {
      rc = HSK_ERECORDMISMATCH;
      goto cleanup;
    }

    if (dns_name_cmp(cname->name, name) != 0) {
      rc = HSK_ERECORDMISMATCH;
      goto cleanup;
    }

    if (canonical->target.type != HSK_INAME)
      goto cleanup;

    char n[1017];

    if (!dns_read_cname_record(cname, n)) {
      rc = HSK_ERECORDMISMATCH;
      goto cleanup;
    }

    if (dns_name_cmp(n, canonical->target.name) != 0) {
      rc = HSK_ERECORDMISMATCH;
      goto cleanup;
    }

    goto cleanup;
  }

  uint8_t hsk_type = type == DNS_A ? HSK_INET4 : HSK_INET6;

  if (!hsk_resource_has(res, hsk_type)) {
    if (msg->ancount != 0) {
      rc = HSK_ERECORDMISMATCH;
      goto cleanup;
    }
    if (msg->nscount != 1) {
      rc = HSK_ERECORDMISMATCH;
      goto cleanup;
    }
    if (msg->authority->type != DNS_SOA) {
      rc = HSK_ERECORDMISMATCH;
      goto cleanup;
    }
    goto cleanup;
  }

  if (msg->ancount == 0) {
    rc = HSK_ERECORDMISMATCH;
    goto cleanup;
  }

  size_t ipsize = type == DNS_A ? 4 : 16;
  int32_t checked = 0;
  dns_record_t *cur = msg->answer;
  hsk_record_t *c, *n;

  for (c = res->records; c; c = c->next) {
    if (c->type == hsk_type) {
      hsk_host_record_t *cc = (hsk_host_record_t *)c;

      if (!cur) {
        rc = HSK_ERECORDMISMATCH;
        goto cleanup;
      }

      if (memcmp(cur->rd, cc->target.addr, ipsize) != 0) {
        rc = HSK_ERECORDMISMATCH;
        goto cleanup;
      }

      cur = cur->next;
      checked += 1;
    }
  }

  if (checked != msg->ancount) {
    rc = HSK_ERECORDMISMATCH;
    goto cleanup;
  }

cleanup:
  if (proof)
    hsk_proof_free(proof);

  if (tld)
    free(tld);

  if (dhash)
    free(dhash);

  if (res)
    hsk_free_resource(res);

  return rc;
}

void
hsk_cleanup() {
  ares_library_cleanup();
}

void
hsk_freehostent(struct hostent *ip) {
  ares_free_hostent(ip);
}

struct hostent *
hsk_gethostbyname(const char *name) {
  if (name == NULL)
    return NULL;

  if (!hsk_is_hsk((char *)name))
    return copy_hostent(gethostbyname(name));

  struct hostent *host = NULL;
  int32_t rc = hsk__gethostbyname((char *)name, AF_INET, &host);

  if (rc != HSK_SUCCESS)
    return NULL;

  return host;
}

struct hostent *
hsk_gethostbyname2(const char *name, int32_t af) {
  if (name == NULL)
    return NULL;

  if (!hsk_is_hsk((char *)name))
    return copy_hostent(gethostbyname2(name, af));

  struct hostent *host = NULL;
  int32_t rc = hsk__gethostbyname((char *)name, af, &host);

  if (rc != HSK_SUCCESS)
    return NULL;

  return host;
}

#ifdef __linux__
static void
check_pf(bool *ipv4, bool *ipv6) {
  struct ifaddrs *ifa = NULL;

  if (getifaddrs(&ifa) != 0) {
    *ipv4 = true;
    *ipv6 = true;
    return;
  }

  *ipv4 = false;
  *ipv6 = false;

  struct ifaddrs *runp;

  for (runp = ifa; runp != NULL; runp = runp->ifa_next) {
    if (runp->ifa_addr->sa_family == AF_INET)
      *ipv4 = true;
    else if (runp->ifa_addr->sa_family == AF_INET6)
      *ipv6 = true;
  }

  freeifaddrs(ifa);
}
#else
static void
check_pf(bool *ipv4, bool *ipv6) {
  *ipv4 = true;
  *ipv6 = true;
}
#endif

void
hsk_freeaddrinfo(struct addrinfo *ai) {
  struct addrinfo *p;

  if (ai != NULL && ai->ai_protocol != IPPROTO_HSK)
    return freeaddrinfo(ai);

  while (ai != NULL) {
    p = ai;
    ai = ai->ai_next;
    if (p->ai_canonname)
      free(p->ai_canonname);
    if (p->ai_addr)
      free(p->ai_addr);
    free(p);
  }
}

int32_t
hsk_getaddrinfo(
  const char *node,
  const char *service,
  const struct addrinfo *hints,
  struct addrinfo **res
) {
  if (!hsk_is_hsk((char *)node))
    return getaddrinfo(node, service, hints, res);

  if (res == NULL)
    return EAI_SYSTEM;

  *res = NULL;

  if (node == NULL)
    return EAI_SYSTEM;

  int32_t flags = AI_V4MAPPED | AI_ADDRCONFIG;
  int32_t af = AF_UNSPEC;
  int32_t st = 0;
  int32_t pt = 0;
  int32_t sp = 0;

  if (hints != NULL) {
    flags = hints->ai_flags;
    af = hints->ai_family;
    st = hints->ai_socktype;
    pt = hints->ai_protocol;
  }

  if (st != 0 && st != SOCK_STREAM && st != SOCK_DGRAM)
    return EAI_SOCKTYPE;

  if (af != AF_UNSPEC && af != AF_INET && af != AF_INET6)
    return EAI_FAMILY;

  // Only for non-dns stuff.
  if (flags & AI_PASSIVE)
    return EAI_BADFLAGS;

  // Only for non-dns stuff.
  if (flags & AI_NUMERICHOST)
    return EAI_BADFLAGS;

  if (service != NULL) {
    // We can't map services to ports yet.
    if (!(flags & AI_NUMERICSERV))
      return EAI_BADFLAGS;

    char *endptr;

    errno = 0;
    sp = strtol(service, &endptr, 10);

    if (errno == ERANGE && (sp == LONG_MAX || sp == LONG_MIN))
      return EAI_SERVICE;

    if (endptr == service)
      return EAI_SERVICE;

    if (sp < 0)
      return EAI_SERVICE;
  }

  if (flags & AI_ADDRCONFIG) {
    bool ipv4 = false;
    bool ipv6 = false;

    check_pf(&ipv4, &ipv6);

    if (!ipv4 || !ipv6) {
      if (ipv4)
        af = AF_INET;
      else if (ipv6)
        af = AF_INET6;
      else
        return EAI_SYSTEM;
    }
  }

  // Return info.
  struct addrinfo *ri = NULL;

  // Parent info.
  struct addrinfo *pi = NULL;

  // Start of ipv6 addrs.
  struct addrinfo *head = NULL;

  // Returned hostent struct.
  struct hostent *host = NULL;

  // Types to iterate through.
  const int32_t types[2] = { AF_INET, AF_INET6 };

  // Return code.
  int32_t code = 0;

  // Figure out start and end.
  int32_t i = af == AF_INET6 && !(flags & AI_V4MAPPED) ? 1 : 0;
  int32_t l = af == AF_INET ? 1 : 2;
  int32_t t = l - i;

  for (; i < l; i++) {
    int32_t rc = hsk__gethostbyname((char *)node, types[i], &host);

    switch (rc) {
      case HSK_SUCCESS:
        break;
      case HSK_ENODATA:
        if (--t == 0) {
          code = EAI_FAIL;
          goto cleanup;
        }
        continue;
      case HSK_EFORMERR:
        code = EAI_FAIL;
        goto cleanup;
      case HSK_ESERVFAIL:
        code = EAI_FAIL;
        goto cleanup;
      case HSK_ENOTIMP:
        code = EAI_FAIL;
        goto cleanup;
      case HSK_EREFUSED:
        code = EAI_FAIL;
        goto cleanup;
      case HSK_EBADQUERY:
        code = EAI_FAIL;
        goto cleanup;
      case HSK_EBADNAME:
        code = EAI_FAIL;
        goto cleanup;
      case HSK_EBADFAMILY:
        code = EAI_FAMILY;
        goto cleanup;
      case HSK_EBADRESP:
        code = EAI_SYSTEM;
        goto cleanup;
      case HSK_ECONNREFUSED:
        code = EAI_FAIL;
        goto cleanup;
      case HSK_ETIMEOUT:
        code = EAI_AGAIN;
        goto cleanup;
      case HSK_EOF:
        code = EAI_SYSTEM;
        goto cleanup;
      case HSK_EFILE:
        code = EAI_SYSTEM;
        goto cleanup;
      case HSK_ENOMEM:
        code = EAI_MEMORY;
        goto cleanup;
      case HSK_EDESTRUCTION:
        code = EAI_SYSTEM;
        goto cleanup;
      case HSK_EBADSTR:
        code = EAI_SYSTEM;
        goto cleanup;
      case HSK_EBADFLAGS:
        code = EAI_BADFLAGS;
        goto cleanup;
      case HSK_ENONAME:
        code = EAI_NONAME;
        goto cleanup;
      case HSK_EBADHINTS:
        code = EAI_BADFLAGS;
        goto cleanup;
      case HSK_ENOTINITIALIZED:
        code = EAI_SYSTEM;
        goto cleanup;
      case HSK_ELOADIPHLPAPI:
        code = EAI_SYSTEM;
        goto cleanup;
      case HSK_EADDRGETNETWORKPARAMS:
        code = EAI_SYSTEM;
        goto cleanup;
      case HSK_ECANCELLED:
        code = EAI_AGAIN;
        goto cleanup;
      default:
        code = EAI_SYSTEM;
        goto cleanup;
    }

    assert(host != NULL);

    if (host->h_addrtype != types[i]) {
      code = EAI_SYSTEM;
      goto cleanup;
    }

    char **addr;
    for (addr = host->h_addr_list; *addr; addr++) {
      struct addrinfo *ai = malloc(sizeof(struct addrinfo));

      if (ai == NULL) {
        code = EAI_MEMORY;
        goto cleanup;
      }

      if (ri == NULL)
        ri = ai;

      ai->ai_flags = flags;
      ai->ai_family = host->h_addrtype;
      ai->ai_socktype = SOCK_DGRAM;
      ai->ai_protocol = IPPROTO_HSK;
      ai->ai_addrlen = 0;
      ai->ai_addr = NULL;
      ai->ai_canonname = NULL;
      ai->ai_next = NULL;

      if (flags & AI_CANONNAME) {
        if (host->h_name) {
          ai->ai_canonname = strdup(host->h_name);
          if (ai->ai_canonname == NULL) {
            free(ai);
            code = EAI_MEMORY;
            goto cleanup;
          }
        }
      }

      if (host->h_addrtype == AF_INET) {
        if (af == AF_INET6 && (flags & AI_V4MAPPED)) {
          struct sockaddr_in6 *sa = malloc(sizeof(struct sockaddr_in6));

          if (sa == NULL) {
            free(ai);
            code = EAI_MEMORY;
            goto cleanup;
          }

          sa->sin6_family = AF_INET6;
          sa->sin6_port = sp;
          sa->sin6_flowinfo = 0;

          struct in_addr *addr4 = (struct in_addr *)*addr;
          unsigned long ipv4 = (unsigned long)addr4->s_addr;
          unsigned long *ipv6 = (unsigned long *)sa->sin6_addr.s6_addr;
          ipv6[0] = 0;
          ipv6[1] = 0;
          ipv6[2] = 0xffff;
          ipv6[3] = ipv4;

          sa->sin6_scope_id = 0;

          ai->ai_addr = (struct sockaddr *)sa;
          ai->ai_addrlen = sizeof(struct sockaddr_in6);
        } else {
          struct sockaddr_in *sa = malloc(sizeof(struct sockaddr_in));

          if (sa == NULL) {
            free(ai);
            code = EAI_MEMORY;
            goto cleanup;
          }

          sa->sin_family = AF_INET;
          sa->sin_port = sp;
          memcpy(&sa->sin_addr, (void *)*addr, sizeof(struct in_addr));

          ai->ai_addr = (struct sockaddr *)sa;
          ai->ai_addrlen = sizeof(struct sockaddr_in);
        }
      } else if (host->h_addrtype == AF_INET6) {
        struct sockaddr_in6 *sa = malloc(sizeof(struct sockaddr_in6));

        if (sa == NULL) {
          free(ai);
          code = EAI_MEMORY;
          goto cleanup;
        }

        sa->sin6_family = AF_INET6;
        sa->sin6_port = sp;
        sa->sin6_flowinfo = 0;
        memcpy(&sa->sin6_addr, (void *)*addr, sizeof(struct in6_addr));
        sa->sin6_scope_id = 0;

        ai->ai_addr = (struct sockaddr *)sa;
        ai->ai_addrlen = sizeof(struct sockaddr_in6);

        if (head == NULL)
          head = ai;
      } else {
        free(ai);
        code = EAI_SYSTEM;
        goto cleanup;
      }

      if (pi)
        pi->ai_next = ai;

      pi = ai;
    }

    ares_free_hostent(host);
    host = NULL;
  }

  if (af == AF_INET6 && (flags & AI_V4MAPPED)) {
    // Found an ipv6 address without AI_ALL,
    // we need to remove the ipv4 addrs.
    if (head && !(flags & AI_ALL)) {
      struct addrinfo *ai;
      for (ai = ri; ai; ai = ai->ai_next) {
        if (ai->ai_next == head)
          break;
      }
      assert(ai != NULL);
      ai->ai_next = NULL;
      hsk_freeaddrinfo(ri);
      ri = head;
    }
  }

  *res = ri;

  return code;

cleanup:
  if (host)
    ares_free_hostent(host);
  if (ri)
    freeaddrinfo(ri);
  return code;
}
