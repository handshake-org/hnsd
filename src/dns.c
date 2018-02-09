#if !defined(WIN32) || defined(WATT32)
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif
#include <strings.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <stdint.h>
#include <limits.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <errno.h>
#include <ctype.h>

#include "c-ares/ares.h"
#include "c-ares/ares_dns.h"
#include "c-ares/nameser.h"

#include "errors.h"
#include "proof.h"
#include "b64.h"
#include "dns.h"

static void
cb_after_query(void *arg, int32_t status, int32_t timeouts, unsigned char *abuf, int32_t alen);

static struct hostent *
copy_hostent(struct hostent *host);

static int32_t
_hsk_init_servers(struct ares_addr_port_node **n);

static int32_t
_hsk_query(const char *name, int32_t type, unsigned char **abuf, int32_t *alen);

static void
cb_after_query(
  void *arg,
  int32_t status,
  int32_t timeouts,
  uint8_t *abuf,
  int32_t alen
);

static int32_t
_hsk_gethostbyname(const char *name, int32_t af, struct hostent **host);

static void
check_pf(bool *ipv4, bool *ipv6);

static const _hsk_ns_t nameservers[] = {
  { .host = "127.0.0.1", .port = 53 },
  { .host = NULL, .port = 0 }
};

static struct ares_addr_port_node *gn = NULL;

bool
hsk_is_hskn(const char *name, size_t len) {
  if (name == NULL)
    return false;

  const char *s = name;

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
hsk_is_hsk(const char *name) {
  if (name == NULL)
    return false;

  return hsk_is_hskn(name, strlen(name));
}

bool
hsk_is_tld(const char *name) {
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
hsk_to_tld(const char *name) {
  if (!hsk_is_tld(name))
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
_hsk_init_servers(struct ares_addr_port_node **n) {
  if (gn != NULL) {
    *n = gn;
    return ARES_SUCCESS;
  }

  *n = NULL;

  struct ares_addr_port_node *pn = NULL;
  const _hsk_ns_t *ns;

  for (ns = nameservers; ns->port != 0; ns++) {
    struct ares_addr_port_node *cn = malloc(sizeof(struct ares_addr_port_node));

    if (cn == NULL)
      return ARES_ENOMEM;

    if (inet_pton(AF_INET, ns->host, &cn->addr.addr4) == 1) {
      cn->family = AF_INET;
    } else if (inet_pton(AF_INET6, ns->host, &cn->addr.addr6) == 1) {
      cn->family = AF_INET6;
    } else {
      return ARES_EBADSTR;
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

  return ARES_SUCCESS;
}

static int32_t
_hsk_query(const char *name, int32_t type, unsigned char **abuf, int32_t *alen) {
  int32_t rc;

  if (abuf == NULL)
    return ARES_EBADSTR;

  *abuf = NULL;

  if (alen == NULL)
    return ARES_EBADSTR;

  *alen = 0;

  if (name == NULL)
    return ARES_EBADSTR;

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

  rc = _hsk_init_servers(&n);

  if (rc != ARES_SUCCESS) {
    ares_destroy(channel);
    return rc;
  }

  rc = ares_set_servers_ports(channel, n);

  if (rc != ARES_SUCCESS) {
    ares_destroy(channel);
    return rc;
  }

  _hsk_query_ret_t ret;
  ares_query(channel, name, ns_c_in, type, cb_after_query, &ret);

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
    if (ret.abuf != NULL)
      free(ret.abuf);
    return ret.status;
  }

  if (ret.abuf == NULL)
    return ARES_ENODATA;

  *abuf = ret.abuf;
  *alen = ret.alen;

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
  _hsk_query_ret_t *ret = (_hsk_query_ret_t *)arg;

  ret->status = 0;
  ret->timeouts = 0;
  ret->abuf = NULL;
  ret->alen = 0;

  if (abuf) {
    ret->abuf = malloc(alen * sizeof(char));
    if (ret->abuf == NULL) {
      ret->status = ARES_ENOMEM;
      return;
    }
    memcpy(ret->abuf, abuf, alen);
    ret->alen = alen;
  }
}

static int32_t
_hsk_gethostbyname(const char *name, int32_t af, struct hostent **host) {
  int32_t rc;

  if (host == NULL)
    return ARES_EBADSTR;

  *host = NULL;

  if (name == NULL)
    return ARES_EBADSTR;

  if (af == 0 || af == AF_UNSPEC)
    af = AF_INET;

  if (af != AF_INET && af != AF_INET6)
    return ARES_EBADSTR;

  int32_t type = ns_t_a;

  if (af == AF_INET6)
    type = ns_t_aaaa;

  uint8_t *abuf;
  int32_t alen;

  rc = _hsk_query(name, type, &abuf, &alen);

  if (rc != ARES_SUCCESS)
    return rc;

  struct ares_addrttl ttls[256];
  int32_t nttls = sizeof(ttls);

  switch (type) {
    case ns_t_a:
      rc = ares_parse_a_reply(abuf, alen, host, ttls, &nttls);
      break;
    case ns_t_aaaa:
      rc = ares_parse_aaaa_reply(
        abuf, alen, host, (struct ares_addr6ttl *)ttls, &nttls);
      break;
    default:
      assert(0);
      break;
  }

  free(abuf);

  return rc;
}

int32_t
hsk_getproof(const char *name, hsk_proof_t **proof) {
  int32_t rc;

  if (proof == NULL)
    return ARES_EBADSTR;

  *proof = NULL;

  if (!hsk_is_tld(name))
    return ARES_EBADSTR;

  uint8_t *abuf;
  int32_t alen;

  rc = _hsk_query(name, ns_t_txt, &abuf, &alen);

  if (rc != ARES_SUCCESS)
    return rc;

  struct ares_txt_ext *txt;

  rc = ares_parse_txt_reply_ext(abuf, alen, &txt);

  free(abuf);

  if (rc != ARES_SUCCESS)
    return rc;

  struct ares_txt_ext *c;
  bool in_proof = false;
  size_t size = 0;

  for (c = txt; c; c = c->next) {
    if (c->record_start) {
      if (in_proof)
        break;

      if (strncmp((char *)c->txt, "hsk:proof", c->length) == 0)
        in_proof = true;

      continue;
    }

    if (!in_proof)
      continue;

    size += c->length;
  }

  if (size > 10240) {
    ares_free_data(txt);
    return ARES_EBADSTR;
  }

  char *b64 = malloc(size + 1);

  if (b64 == NULL) {
    ares_free_data(txt);
    return ARES_ENOMEM;
  }

  char *s = b64;
  in_proof = false;

  for (c = txt; c; c = c->next) {
    if (c->record_start) {
      if (in_proof)
        break;

      if (strncmp((char *)c->txt, "hsk:proof", c->length) == 0)
        in_proof = true;

      continue;
    }

    if (!in_proof)
      continue;

    memcpy(s, c->txt, c->length);
    s += c->length;
  }

  *s = '\0';

  ares_free_data(txt);

  hsk_raw_node_t *head = NULL;
  hsk_raw_node_t *parent = NULL;
  hsk_raw_node_t *grandparent = NULL;

  s = b64;

  for (;;) {
    int32_t i = 0;
    char *last = s;

    for (s = last; *s; s++) {
      if (*s == ':')
        break;
      i += 1;
    }

    hsk_raw_node_t *node = malloc(sizeof(hsk_raw_node_t));

    if (node == NULL) {
      free(b64);
      return ARES_ENOMEM;
    }

    node->next = NULL;
    node->data = hsk_b64_decode(last, i, &node->len);

    if (node->data == NULL) {
      free(b64);
      free(node);
      return ARES_ENOMEM;
    }

    if (head == NULL)
      head = node;

    if (parent)
      parent->next = node;

    grandparent = parent;
    parent = node;

    if (*s == 0)
      break;

    s += 1;
  }

  free(b64);

  if (!head)
    return ARES_EBADSTR;

  if (!head->next) {
    free(head->data);
    free(head);
    return ARES_EBADSTR;
  }

  if (!head->next->next) {
    free(head->next->data);
    free(head->next);
    free(head->data);
    free(head);
    return ARES_EBADSTR;
  }

  hsk_proof_t *p = malloc(sizeof(hsk_proof_t));

  if (head->len != 32 || p == NULL) {
    if (p)
      free(p);
    hsk_raw_node_t *c, *n;
    for (c = head; c; c = n) {
      n = c->next;
      free(c->data);
      free(c);
    }
    if (p)
      return ARES_EBADSTR;
    return ARES_ENOMEM;
  }

  assert(parent != NULL);
  assert(grandparent != NULL);

  p->block_hash = head->data;
  p->nodes = head->next;
  free(head);
  p->data = parent;
  grandparent->next = NULL;

  *proof = p;

  return ARES_SUCCESS;
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

  if (!hsk_is_hsk(name))
    return copy_hostent(gethostbyname(name));

  struct hostent *host = NULL;
  int32_t rc = _hsk_gethostbyname(name, AF_INET, &host);

  if (rc != ARES_SUCCESS)
    return NULL;

  return host;
}

struct hostent *
hsk_gethostbyname2(const char *name, int32_t af) {
  if (name == NULL)
    return NULL;

  if (!hsk_is_hsk(name))
    return copy_hostent(gethostbyname2(name, af));

  struct hostent *host = NULL;
  int32_t rc = _hsk_gethostbyname(name, af, &host);

  if (rc != ARES_SUCCESS)
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
  if (!hsk_is_hsk(node))
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
    int32_t rc = _hsk_gethostbyname(node, types[i], &host);

    switch (rc) {
      case ARES_SUCCESS:
        break;
      case ARES_ENODATA:
        if (--t == 0) {
          code = EAI_FAIL;
          goto cleanup;
        }
        continue;
      case ARES_EFORMERR:
        code = EAI_FAIL;
        goto cleanup;
      case ARES_ESERVFAIL:
        code = EAI_FAIL;
        goto cleanup;
      case ARES_ENOTIMP:
        code = EAI_FAIL;
        goto cleanup;
      case ARES_EREFUSED:
        code = EAI_FAIL;
        goto cleanup;
      case ARES_EBADQUERY:
        code = EAI_FAIL;
        goto cleanup;
      case ARES_EBADNAME:
        code = EAI_FAIL;
        goto cleanup;
      case ARES_EBADFAMILY:
        code = EAI_FAMILY;
        goto cleanup;
      case ARES_EBADRESP:
        code = EAI_SYSTEM;
        goto cleanup;
      case ARES_ECONNREFUSED:
        code = EAI_FAIL;
        goto cleanup;
      case ARES_ETIMEOUT:
        code = EAI_AGAIN;
        goto cleanup;
      case ARES_EOF:
        code = EAI_SYSTEM;
        goto cleanup;
      case ARES_EFILE:
        code = EAI_SYSTEM;
        goto cleanup;
      case ARES_ENOMEM:
        code = EAI_MEMORY;
        goto cleanup;
      case ARES_EDESTRUCTION:
        code = EAI_SYSTEM;
        goto cleanup;
      case ARES_EBADSTR:
        code = EAI_SYSTEM;
        goto cleanup;
      case ARES_EBADFLAGS:
        code = EAI_BADFLAGS;
        goto cleanup;
      case ARES_ENONAME:
        code = EAI_NONAME;
        goto cleanup;
      case ARES_EBADHINTS:
        code = EAI_BADFLAGS;
        goto cleanup;
      case ARES_ENOTINITIALIZED:
        code = EAI_SYSTEM;
        goto cleanup;
      case ARES_ELOADIPHLPAPI:
        code = EAI_SYSTEM;
        goto cleanup;
      case ARES_EADDRGETNETWORKPARAMS:
        code = EAI_SYSTEM;
        goto cleanup;
      case ARES_ECANCELLED:
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
