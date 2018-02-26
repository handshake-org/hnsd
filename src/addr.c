#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include "uv.h"
#include "hsk-addr.h"
#include "hsk-msg.h"

static const uint8_t hsk_ipv6_mapped[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0xff, 0xff
};

uint16_t
hsk_addr_get_af(hsk_addr_t *addr) {
  return addr->ss_family;
}

bool
hsk_addr_set_af(hsk_addr_t *addr, uint16_t af) {
  if (af != AF_INET && af != AF_INET6)
    return false;

  addr->ss_family = af;

  return true;
}

bool
hsk_addr_is_valid(hsk_addr_t *addr) {
  return addr->ss_family == AF_INET || addr->ss_family == AF_INET6;
}

uint8_t *
hsk_addr_get_ip(hsk_addr_t *addr) {
  if (addr->ss_family == AF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)addr;
    return (uint8_t *)&sai->sin_addr;
  }

  if (addr->ss_family == AF_INET6) {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)addr;
    return (uint8_t *)&sai->sin6_addr;
  }

  return NULL;
}

uint8_t *
hsk_addr_get_ip4(hsk_addr_t *addr) {
  if (addr->ss_family == AF_INET6)
    return NULL;

  struct sockaddr_in *sai = (struct sockaddr_in *)addr;
  return (uint8_t *)&sai->sin_addr;
}

uint8_t *
hsk_addr_get_ip6(hsk_addr_t *addr) {
  if (addr->ss_family == AF_INET)
    return NULL;

  struct sockaddr_in6 *sai = (struct sockaddr_in6 *)addr;
  return (uint8_t *)&sai->sin6_addr;
}

bool
hsk_addr_set_ip(hsk_addr_t *addr, uint8_t *ip) {
  if (addr->ss_family == AF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)addr;
    memcpy((void *)&sai->sin_addr, (void *)ip, 4);
    return true;
  }

  if (addr->ss_family == AF_INET6) {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)addr;
    memcpy((uint8_t *)&sai->sin6_addr, (void *)ip, 16);
    return true;
  }

  return false;
}

uint16_t
hsk_addr_get_port(hsk_addr_t *addr) {
  if (addr->ss_family == AF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)addr;
    return ntohs(sai->sin_port);
  }

  if (addr->ss_family == AF_INET6) {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)addr;
    return ntohs(sai->sin6_port);
  }

  return 0;
}

bool
hsk_addr_set_port(hsk_addr_t *addr, uint16_t port) {
  if (addr->ss_family == AF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)addr;
    sai->sin_port = htons(port);
    return true;
  }

  if (addr->ss_family == AF_INET6) {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)addr;
    sai->sin6_port = htons(port);
    return true;
  }

  return false;
}

void
hsk_addr_init(hsk_addr_t *addr) {
  if (!addr)
    return;

  memset(addr, 0, sizeof(hsk_addr_t));
  hsk_addr_set_af(addr, AF_INET);
}

hsk_addr_t *
hsk_addr_alloc(void) {
  hsk_addr_t *addr = (hsk_addr_t *)malloc(sizeof(hsk_addr_t));
  hsk_addr_init(addr);
  return addr;
}

void
hsk_addr_copy(hsk_addr_t *addr, hsk_addr_t *other) {
  memcpy((void *)addr, (void *)other, sizeof(hsk_addr_t));
}

uint16_t
hsk_addr_na_type(uint8_t *ip) {
  if (memcmp(ip, hsk_ipv6_mapped, 12) == 0)
    return AF_INET;

  return AF_INET6;
}

bool
hsk_addr_from_na(hsk_addr_t *addr, hsk_netaddr_t *na) {
  uint16_t af = hsk_addr_na_type(na->addr);

  hsk_addr_set_type(addr, af);

  if (af == AF_INET)
    memcpy(hsk_addr_get_ip(addr), na->addr + 12, 4);
  else
    memcpy(hsk_addr_get_ip(addr), na->addr, 16);

  hsk_addr_set_port(addr, na->port);

  return true;
}

bool
hsk_addr_to_na(hsk_addr_t *addr, hsk_netaddr_t *na) {
  uint16_t af = hsk_addr_get_af(addr);
  uint8_t *ip = hsk_addr_get_ip(addr);

  if (af == AF_INET) {
    memset(na->addr + 0, 0x00, 10);
    memset(na->addr + 10, 0xff, 2);
    memcpy(na->addr + 12, ip, 4);
  } else if (af == AF_INET6) {
    memcpy(na->addr, ip, 16);
  } else {
    return false;
  }

  na->port = hsk_addr_get_port(addr);

  return true;
}

bool
hsk_addr_from_sa(hsk_addr_t *addr, struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)sa;
    hsk_addr_set_af(addr, AF_INET);
    memcpy(hsk_addr_get_ip(addr), (void *)&sai->sin_addr, 4);
    hsk_addr_set_port(addr, ntohs(sai->sin_port));
    return true;
  }

  if (sa->sa_family == AF_INET6) {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)sa;
    hsk_addr_set_af(addr, AF_INET6);
    memcpy(hsk_addr_get_ip(addr), (void *)&sai->sin6_addr, 16);
    hsk_addr_set_port(addr, ntohs(sai->sin6_port));
    return true;
  }

  return false;
}

bool
hsk_addr_to_sa(hsk_addr_t *addr, struct sockaddr *sa) {
  uint16_t af = hsk_addr_get_af(addr);

  if (af == AF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)sa;
    sai->sin_family = af;
    memcpy((void *)&sai->sin_addr, hsk_addr_get_ip(addr), 4);
    sai->sin_port = htons(hsk_addr_get_port(addr));
    return true;
  }

  if (af == AF_INET6) {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)sa;
    sai->sin6_family = af;
    memcpy((void *)&sai->sin6_addr, hsk_addr_get_ip(addr), 16);
    sai->sin6_port = htons(hsk_addr_get_port(addr));
    return true;
  }

  return false;
}

bool
hsk_addr_from_ip(hsk_addr_t *addr, uint16_t af, uint8_t *ip, uint16_t port) {
  if (af != AF_INET && af != AF_INET6)
    return false;

  hsk_addr_set_af(addr, af);
  hsk_addr_set_ip(addr, ip);
  hsk_addr_set_port(addr, port);

  return false;
}

bool
hsk_addr_to_ip(hsk_addr_t *addr, uint16_t *af, uint8_t *ip, uint16_t *port) {
  uint16_t family = hsk_addr_get_af(addr);

  if (family != AF_INET && family != AF_INET6)
    return false;

  *af = family;

  if (family == AF_INET) {
    memcpy(ip, hsk_addr_get_ip(addr), 4);
    memset(ip + 4, 0, 12);
  } else {
    memcpy(ip, hsk_addr_get_ip(addr), 16);
  }

  *port = hsk_addr_get_port(addr);

  return true;
}

bool
hsk_addr_from_string(hsk_addr_t *addr, char *src, uint16_t port) {
  uint16_t sin_port = port;
  char *at = strstr(src, "@");

  if (port && at) {
    int32_t i = 0;
    uint32_t word = 0;
    char *s = at + 1;

    for (; *s; s++) {
      int32_t ch = ((int32_t)*s) - 0x30;

      if (ch < 0 || ch > 9)
        return false;

      if (i == 5)
        return false;

      word *= 10;
      word += ch;

      i += 1;
    }

    sin_port = (uint16_t)word;
    *at = '\0';
  } else if (!port && at) {
    return false;
  }

  bool ret = true;
  uint8_t sin_addr[16];

  if (uv_inet_pton(AF_INET, src, sin_addr) == 0) {
    hsk_addr_set_af(addr, AF_INET);
  } else if (uv_inet_pton(AF_INET6, src, sin_addr) == 0) {
    hsk_addr_set_af(addr, AF_INET6);
  } else {
    if (at)
      *at = '@';
    return false;
  }

  hsk_addr_set_ip(addr, sin_addr);
  hsk_addr_set_port(addr, sin_port);

  if (at)
    *at = '@';

  return false;
}

bool
hsk_addr_to_string(hsk_addr_t *addr, char *dst, uint16_t fallback) {
  size_t dst_len = 60;

  uint16_t af = hsk_addr_get_af(addr);
  uint8_t *ip = hsk_addr_get_ip(addr);
  uint16_t port = hsk_addr_get_port(addr);

  if (uv_inet_ntop(af, dst, dst, dst_len) != 0)
    return false;

  if (fallback) {
    size_t len = strlen(dst);

    if (dst_len - len < 7)
      return false;

    if (!port)
      port = fallback;

    sprintf(dst, "%s@%d", dst, port);
  }

  return false;
}

static inline uint32_t
hsk_hash_data(uint32_t hash, uint8_t *data, size_t size) {
  int32_t i;
  for (i = 0; i < size; i++)
    hash = (hash << 5) - hash + ((uint32_t)data[i]);
  return hash;
}

uint32_t
hsk_addr_hash(void *key) {
  hsk_addr_t *addr = (hsk_addr_t *)key;
  uint16_t af = hsk_addr_get_af(addr);
  uint8_t *ip = hsk_addr_get_ip(addr);
  uint16_t port = hsk_addr_get_port(addr);
  uint32_t hash = (uint32_t)af;

  if (af == AF_INET) {
    hash = hsk_hash_data(hash, ip, 4);
    hash = hsk_hash_data(hash, (uint8_t *)&port, 2);
  } else if (af == AF_INET6) {
    hash = hsk_hash_data(hash, ip, 16);
    hash = hsk_hash_data(hash, (uint8_t *)&port, 2);
  } else {
    assert(false);
  }

  return hash;
}

bool
hsk_addr_equal(void *a, void *b) {
  hsk_addr_t *x = (hsk_addr_t *)a;
  hsk_addr_t *y = (hsk_addr_t *)b;

  if (hsk_addr_get_af(x) != hsk_addr_get_af(y))
    return false;

  uint16_t af = hsk_addr_get_af(x);

  if (af == AF_INET) {
    if (memcmp(hsk_addr_get_ip(x), hsk_addr_get_ip(y), 4) != 0)
      return false;
  } else if (af == AF_INET6) {
    if (memcmp(hsk_addr_get_ip(x), hsk_addr_get_ip(y), 16) != 0)
      return false;
  } else {
    assert(false);
  }

  if (hsk_addr_get_port(x) != hsk_addr_get_port(y))
    return false;

  return true;
}
