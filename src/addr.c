#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "addr.h"
#include "base32.h"
#include "bio.h"
#include "constants.h"
#include "map.h"
#include "platform-net.h"
#include "uv.h"

static const uint8_t hsk_ip4_mapped[12] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0xff, 0xff
};

static const uint8_t hsk_local_ip[16] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x01
};

static const uint8_t hsk_zero_ip[16] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static const uint8_t hsk_rfc6052[12] = {
  0x00, 0x64, 0xff, 0x9b,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static const uint8_t hsk_rfc4862[8] = {
  0xfe, 0x80, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static const uint8_t hsk_rfc6145[12] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0xff, 0xff, 0x00, 0x00
};

static const uint8_t hsk_shifted[9] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0xff,
  0xff
};

static const uint8_t hsk_tor_onion[6] = {
  0xfd, 0x87, 0xd8, 0x7e,
  0xeb, 0x43
};

static const uint8_t hsk_zero_pub[33] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00
};

void
hsk_addr_init(hsk_addr_t *addr) {
  assert(addr);
  memset(addr, 0x00, sizeof(hsk_addr_t));
}

hsk_addr_t *
hsk_addr_alloc(void) {
  hsk_addr_t *addr = (hsk_addr_t *)malloc(sizeof(hsk_addr_t));
  if (addr)
    hsk_addr_init(addr);
  return addr;
}

hsk_addr_t *
hsk_addr_clone(const hsk_addr_t *other) {
  assert(other);

  hsk_addr_t *addr = hsk_addr_alloc();

  if (!addr)
    return NULL;

  hsk_addr_copy(addr, other);

  return addr;
}

void
hsk_addr_copy(hsk_addr_t *addr, const hsk_addr_t *other) {
  assert(addr && other);
  memcpy((void *)addr, (void *)other, sizeof(hsk_addr_t));
}

bool
hsk_addr_is_mapped(const hsk_addr_t *addr) {
  assert(addr);
  return memcmp(addr->ip, hsk_ip4_mapped, sizeof(hsk_ip4_mapped)) == 0;
}

bool
hsk_addr_is_ip4(const hsk_addr_t *addr) {
  assert(addr);
  return hsk_addr_is_mapped(addr);
}

bool
hsk_addr_is_ip6(const hsk_addr_t *addr) {
  assert(addr);
  return !hsk_addr_is_mapped(addr) && !hsk_addr_is_onion(addr);
}

bool
hsk_addr_is_onion(const hsk_addr_t *addr) {
  assert(addr);
  return memcmp(addr->ip, hsk_tor_onion, sizeof(hsk_tor_onion)) == 0;
}

bool
hsk_addr_has_key(const hsk_addr_t *addr) {
  assert(addr);
  return memcmp(addr->key, (void *)hsk_zero_pub, sizeof(hsk_zero_pub)) != 0;
}

int
hsk_addr_get_af(const hsk_addr_t *addr) {
  assert(addr);
  return hsk_addr_is_mapped(addr) ? AF_INET : AF_INET6;
}

uint8_t
hsk_addr_get_type(const hsk_addr_t *addr) {
  assert(addr);
  return addr->type;
}

bool
hsk_addr_set_type(hsk_addr_t *addr, uint8_t type) {
  assert(addr);
  addr->type = type;
  return true;
}

const uint8_t *
hsk_addr_get_ip(const hsk_addr_t *addr) {
  assert(addr);
  if (hsk_addr_is_ip6(addr))
    return addr->ip;
  return &addr->ip[12];
}

bool
hsk_addr_set_ip(hsk_addr_t *addr, int af, const uint8_t *ip) {
  assert(addr && ip);

  if (af == AF_INET) {
    memset(&addr->ip[0], 0x00, 10);
    memset(&addr->ip[10], 0xff, 2);
    memcpy(&addr->ip[12], ip, 4);
    memset(&addr->ip[16], 0x00, 20);
    return true;
  }

  if (af == AF_INET6) {
    memcpy(&addr->ip[0], ip, 16);
    memset(&addr->ip[16], 0x00, 20);
    return true;
  }

  return false;
}

uint16_t
hsk_addr_get_port(const hsk_addr_t *addr) {
  assert(addr);
  return addr->port;
}

bool
hsk_addr_set_port(hsk_addr_t *addr, uint16_t port) {
  assert(addr);
  addr->port = port;
  return true;
}

bool
hsk_addr_from_na(hsk_addr_t *addr, const hsk_netaddr_t *na) {
  assert(addr && na);
  hsk_addr_copy(addr, &na->addr);
  return true;
}

bool
hsk_addr_to_na(const hsk_addr_t *addr, hsk_netaddr_t *na) {
  assert(addr && na);
  hsk_addr_copy(&na->addr, addr);
  return true;
}

bool
hsk_addr_from_sa(hsk_addr_t *addr, const struct sockaddr *sa) {
  assert(addr && sa);

  hsk_addr_init(addr);

  if (sa->sa_family == AF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)sa;
    addr->type = 0;
    hsk_addr_set_ip(addr, AF_INET, (const uint8_t *)&sai->sin_addr);
    addr->port = ntohs(sai->sin_port);
    return true;
  }

  if (sa->sa_family == AF_INET6) {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)sa;
    addr->type = 0;
    hsk_addr_set_ip(addr, AF_INET6, (const uint8_t *)&sai->sin6_addr);
    addr->port = ntohs(sai->sin6_port);
    return true;
  }

  return false;
}

bool
hsk_addr_to_sa(const hsk_addr_t *addr, struct sockaddr *sa) {
  assert(addr && sa);

  int af = hsk_addr_get_af(addr);

  if (af == AF_INET) {
    struct sockaddr_in *sai = (struct sockaddr_in *)sa;
    sai->sin_family = AF_INET;
    memcpy((void *)&sai->sin_addr, &addr->ip[12], 4);
    sai->sin_port = htons(addr->port);
    return true;
  }

  if (af == AF_INET6) {
    struct sockaddr_in6 *sai = (struct sockaddr_in6 *)sa;
    sai->sin6_family = AF_INET6;
    memcpy((void *)&sai->sin6_addr, &addr->ip[0], 16);
    sai->sin6_port = htons(addr->port);
    return true;
  }

  return false;
}

bool
hsk_addr_from_ip(
  hsk_addr_t *addr,
  int af,
  const uint8_t *ip,
  uint16_t port
) {
  assert(addr && ip);

  hsk_addr_init(addr);

  if (!hsk_addr_set_ip(addr, af, ip))
    return false;

  addr->port = port;

  return false;
}

bool
hsk_addr_to_ip(
  const hsk_addr_t *addr,
  int *af,
  uint8_t *ip,
  uint16_t *port
) {
  assert(addr && ip);

  int family = hsk_addr_get_af(addr);

  *af = family;

  if (family == AF_INET)
    memcpy(&ip[0], &addr->ip[12], 4);
  else
    memcpy(&ip[0], &addr->ip[0], 16);

  *port = addr->port;

  return true;
}

bool
hsk_addr_from_string(hsk_addr_t *addr, const char *src, uint16_t port) {
  assert(addr && src);

  hsk_addr_init(addr);

  char *at = strchr(src, '@');

  if (at) {
    char pubkey[54];
    size_t pubkey_len = at - src;

    if (pubkey_len > 53)
      return false;

    memcpy(pubkey, src, pubkey_len);
    pubkey[pubkey_len] = '\0';

    if (hsk_base32_decode_size(pubkey) != 33)
      return false;

    if (hsk_base32_decode(pubkey, addr->key, false) == -1)
      return false;

    src = &at[1];
  }

  char host[INET6_ADDRSTRLEN + 1];
  char *host_start;
  size_t host_len;
  char *port_s = NULL;

  if (src[0] == '[') {
    char *bracket = strchr(src, ']');

    if (!bracket)
      return false;

    host_start = (char *)&src[1];
    host_len = bracket - host_start;

    if (bracket[1] == ':')
      port_s = &bracket[2];
    else if (bracket[1] == '\0')
      port_s = NULL;
    else
      return false;
  } else {
    char *colon = strchr(src, ':');

    // ipv6 with no port.
    if (colon && strchr(&colon[1], ':'))
      colon = NULL;

    host_start = (char *)src;

    if (colon) {
      host_len = colon - src;
      port_s = &colon[1];
    } else {
      host_len = strlen(src);
      port_s = NULL;
    }
  }

  if (host_len > INET6_ADDRSTRLEN)
    return false;

  memcpy(host, host_start, host_len);
  host[host_len] = '\0';

  uint16_t sin_port = port;

  if (port && port_s) {
    int i = 0;
    uint32_t word = 0;
    char *s = port_s;

    for (; *s; s++) {
      int ch = ((int)*s) - 0x30;

      if (ch < 0 || ch > 9)
        return false;

      if (i == 5)
        return false;

      word *= 10;
      word += ch;

      i += 1;
    }

    sin_port = (uint16_t)word;
  } else if (!port && port_s) {
    return false;
  }

  uint8_t sin_addr[16];
  uint16_t af;

  memset(&sin_addr[0], 0x00, 16);

  if (uv_inet_pton(AF_INET, host, sin_addr) == 0) {
    af = AF_INET;
  } else if (uv_inet_pton(AF_INET6, host, sin_addr) == 0) {
    af = AF_INET6;
  } else {
    return false;
  }

  addr->type = 0;
  assert(hsk_addr_set_ip(addr, af, sin_addr));
  addr->port = sin_port;

  return true;
}

bool
hsk_addr_to_string(
  const hsk_addr_t *addr,
  char *dst,
  size_t dst_len,
  uint16_t fb
) {
  assert(addr && dst);

  int af = hsk_addr_get_af(addr);
  const uint8_t *ip = hsk_addr_get_ip(addr);
  uint16_t port = addr->port;

  if (uv_inet_ntop(af, ip, dst, dst_len) != 0)
    return false;

  if (fb) {
    size_t len = strlen(dst);
    size_t need = af == AF_INET6 ? 9 : 7;

    if (dst_len - len < need)
      return false;

    if (!port)
      port = fb;

    // XXX Not thread safe.
    static char tmp[HSK_MAX_HOST];

    if (af == AF_INET6) {
      assert(len + need < HSK_MAX_HOST);
      sprintf(tmp, "[%s]:%u", dst, port);
    } else {
      sprintf(tmp, "%s:%u", dst, port);
    }

    strcpy(dst, tmp);
  }

  return true;
}

bool
hsk_addr_to_full(
  const hsk_addr_t *addr,
  char *dst,
  size_t dst_len,
  uint16_t fb
) {
  if (!hsk_addr_to_string(addr, dst, dst_len, fb))
    return false;

  if (!hsk_addr_has_key(addr))
    return true;

  size_t len = strlen(dst);
  size_t size = hsk_base32_encode_size(addr->key, 33, false);

  if (dst_len - len < size + 1)
    return false;

  assert(size <= 54);
  assert(len + (size - 1) + 1 < HSK_MAX_HOST);

  char b32[54];
  hsk_base32_encode(addr->key, 33, b32, false);

  // XXX Not thread safe.
  static char tmp[HSK_MAX_HOST];
  sprintf(tmp, "%s@%s", b32, dst);
  strcpy(dst, tmp);

  return true;
}

bool
hsk_addr_to_at(const hsk_addr_t *addr, char *dst, size_t dst_len, uint16_t fb) {
  assert(addr && dst);

  int af = hsk_addr_get_af(addr);
  const uint8_t *ip = hsk_addr_get_ip(addr);
  uint16_t port = addr->port;

  if (uv_inet_ntop(af, ip, dst, dst_len) != 0)
    return false;

  if (fb) {
    size_t len = strlen(dst);

    if (dst_len - len < 7)
      return false;

    if (!port)
      port = fb;

    // XXX Not thread safe.
    static char tmp[HSK_MAX_HOST];
    sprintf(tmp, "%s@%u", dst, port);
    strcpy(dst, tmp);
  }

  return true;
}

bool
hsk_addr_localize(hsk_addr_t *addr) {
  assert(addr);

  if (addr->type != 0)
    return false;

  if (hsk_addr_is_null(addr)) {
    if (hsk_addr_is_ip4(addr)) {
      addr->ip[12] = 127;
      addr->ip[15] = 1;
    } else {
      addr->ip[15] = 1;
    }
  }

  return true;
}

bool
hsk_sa_from_string(struct sockaddr *sa, const char *src, uint16_t port) {
  assert(sa && src);

  hsk_addr_t addr;

  if (!hsk_addr_from_string(&addr, src, port))
    return false;

  return hsk_addr_to_sa(&addr, sa);
}

bool
hsk_sa_to_string(
  const struct sockaddr *sa,
  char *dst,
  size_t dst_len,
  uint16_t fb
) {
  assert(sa && dst);

  hsk_addr_t addr;

  if (!hsk_addr_from_sa(&addr, sa))
    return false;

  if (!hsk_addr_to_string(&addr, dst, dst_len, fb))
    return false;

  return true;
}

bool
hsk_sa_to_at(
  const struct sockaddr *sa,
  char *dst,
  size_t dst_len,
  uint16_t fb
) {
  assert(sa && dst);

  hsk_addr_t addr;

  if (!hsk_addr_from_sa(&addr, sa))
    return false;

  if (!hsk_addr_to_at(&addr, dst, dst_len, fb))
    return false;

  return true;
}

bool
hsk_sa_copy(struct sockaddr *sa, const struct sockaddr *other) {
  assert(sa && other);

  if (other->sa_family != AF_INET && other->sa_family != AF_INET6)
    return false;

  size_t size = 0;

  // Note: sockaddr is the worst thing ever created.
  if (other->sa_family == AF_INET)
    size = sizeof(struct sockaddr_in);
  else
    size = sizeof(struct sockaddr_in6);

  memcpy((void *)sa, (void *)other, size);

  return true;
}

bool
hsk_sa_localize(struct sockaddr *sa) {
  hsk_addr_t addr;

  if (!hsk_addr_from_sa(&addr, sa))
    return false;

  if (!hsk_addr_localize(&addr))
    return false;

  if (!hsk_addr_to_sa(&addr, sa))
    return false;

  return true;
}

uint32_t
hsk_addr_hash(const void *key) {
  hsk_addr_t *addr = (hsk_addr_t *)key;
  assert(addr);
  return hsk_map_tweak3(addr->ip, 36, addr->type + 1, addr->port);
}

bool
hsk_addr_equal(const void *a, const void *b) {
  assert(a && b);

  hsk_addr_t *x = (hsk_addr_t *)a;
  hsk_addr_t *y = (hsk_addr_t *)b;

  if (x->type != y->type)
    return false;

  if (memcmp(x->ip, y->ip, 36) != 0)
    return false;

  if (x->port != y->port)
    return false;

  return true;
}

bool
hsk_addr_is_null(const hsk_addr_t *addr) {
  assert(addr);

  if (hsk_addr_is_ip4(addr)) {
    // 0.0.0.0
    return addr->ip[12] == 0
        && addr->ip[13] == 0
        && addr->ip[14] == 0
        && addr->ip[15] == 0;
  }

  // ::
  return memcmp(addr->ip, hsk_zero_ip, 16) == 0;
}

bool
hsk_addr_is_broadcast(const hsk_addr_t *addr) {
  assert(addr);

  if (!hsk_addr_is_ip4(addr))
    return false;

  // 255.255.255.255
  return addr->ip[12] == 255
      && addr->ip[13] == 255
      && addr->ip[14] == 255
      && addr->ip[15] == 255;
}

bool
hsk_addr_is_rfc1918(const hsk_addr_t *addr) {
  assert(addr);

  if (!hsk_addr_is_ip4(addr))
    return false;

  if (addr->ip[12] == 10)
    return true;

  if (addr->ip[12] == 192 && addr->ip[13] == 168)
    return true;

  if (addr->ip[12] == 172 && (addr->ip[13] >= 16 && addr->ip[13] <= 31))
    return true;

  return false;
}

bool
hsk_addr_is_rfc2544(const hsk_addr_t *addr) {
  assert(addr);

  if (!hsk_addr_is_ip4(addr))
    return false;

  if (addr->ip[12] == 198 && (addr->ip[13] == 18 || addr->ip[13] == 19))
    return true;

  if (addr->ip[12] == 169 && addr->ip[13] == 254)
    return true;

  return false;
}

bool
hsk_addr_is_rfc3927(const hsk_addr_t *addr) {
  assert(addr);

  if (!hsk_addr_is_ip4(addr))
    return false;

  if (addr->ip[12] == 169 && addr->ip[13] == 254)
    return true;

  return false;
}

bool
hsk_addr_is_rfc6598(const hsk_addr_t *addr) {
  assert(addr);

  if (!hsk_addr_is_ip4(addr))
    return false;

  if (addr->ip[12] == 100
      && (addr->ip[13] >= 64 && addr->ip[13] <= 127)) {
    return true;
  }

  return false;
}

bool
hsk_addr_is_rfc5737(const hsk_addr_t *addr) {
  assert(addr);

  if (!hsk_addr_is_ip4(addr))
    return false;

  if (addr->ip[12] == 192
      && (addr->ip[13] == 0 && addr->ip[14] == 2)) {
    return true;
  }

  if (addr->ip[12] == 198 && addr->ip[13] == 51 && addr->ip[14] == 100)
    return true;

  if (addr->ip[12] == 203 && addr->ip[13] == 0 && addr->ip[14] == 113)
    return true;

  return false;
}

bool
hsk_addr_is_rfc3849(const hsk_addr_t *addr) {
  assert(addr);

  if (addr->ip[0] == 0x20 && addr->ip[1] == 0x01
      && addr->ip[2] == 0x0d && addr->ip[3] == 0xb8) {
    return true;
  }

  return false;
}

bool
hsk_addr_is_rfc3964(const hsk_addr_t *addr) {
  assert(addr);

  if (addr->ip[0] == 0x20 && addr->ip[1] == 0x02)
    return true;

  return false;
}

bool
hsk_addr_is_rfc6052(const hsk_addr_t *addr) {
  assert(addr);
  return memcmp(addr->ip, hsk_rfc6052, sizeof(hsk_rfc6052)) == 0;
}

bool
hsk_addr_is_rfc4380(const hsk_addr_t *addr) {
  assert(addr);

  if (addr->ip[0] == 0x20 && addr->ip[1] == 0x01
      && addr->ip[2] == 0x00 && addr->ip[3] == 0x00) {
    return true;
  }

  return false;
}

bool
hsk_addr_is_rfc4862(const hsk_addr_t *addr) {
  assert(addr);
  return memcmp(addr->ip, hsk_rfc4862, sizeof(hsk_rfc4862)) == 0;
}

bool
hsk_addr_is_rfc4193(const hsk_addr_t *addr) {
  assert(addr);

  if ((addr->ip[0] & 0xfe) == 0xfc)
    return true;

  return false;
}

bool
hsk_addr_is_rfc6145(const hsk_addr_t *addr) {
  assert(addr);
  return memcmp(addr->ip, hsk_rfc6145, sizeof(hsk_rfc6145)) == 0;
}

bool
hsk_addr_is_rfc4843(const hsk_addr_t *addr) {
  assert(addr);

  if (addr->ip[0] == 0x20 && addr->ip[1] == 0x01
      && addr->ip[2] == 0x00 && (addr->ip[3] & 0xf0) == 0x10) {
    return true;
  }

  return false;
}

bool
hsk_addr_is_local(const hsk_addr_t *addr) {
  assert(addr);

  if (hsk_addr_is_ip4(addr)) {
    if (addr->ip[12] == 127 && addr->ip[13] == 0)
      return true;
    return false;
  }

  if (memcmp(addr->ip, hsk_local_ip, sizeof(hsk_local_ip)) == 0)
    return true;

  return false;
}

bool
hsk_addr_is_multicast(const hsk_addr_t *addr) {
  assert(addr);

  if (hsk_addr_is_ip4(addr)) {
    if ((addr->ip[12] & 0xf0) == 0xe0)
      return true;
    return false;
  }

  return addr->ip[0] == 0xff;
}

bool
hsk_addr_is_valid(const hsk_addr_t *addr) {
  assert(addr);

  if (addr->type != 0)
    return false;

  if (memcmp(addr->ip, hsk_shifted, sizeof(hsk_shifted)) == 0)
    return false;

  if (hsk_addr_is_null(addr))
    return false;

  if (hsk_addr_is_broadcast(addr))
    return false;

  if (hsk_addr_is_rfc3849(addr))
    return false;

  return true;
}

bool
hsk_addr_is_routable(const hsk_addr_t *addr) {
  assert(addr);

  if (!hsk_addr_is_valid(addr))
    return false;

  if (hsk_addr_is_rfc1918(addr))
    return false;

  if (hsk_addr_is_rfc2544(addr))
    return false;

  if (hsk_addr_is_rfc3927(addr))
    return false;

  if (hsk_addr_is_rfc4862(addr))
    return false;

  if (hsk_addr_is_rfc6598(addr))
    return false;

  if (hsk_addr_is_rfc5737(addr))
    return false;

  if (hsk_addr_is_rfc4193(addr) && !hsk_addr_is_onion(addr))
    return false;

  if (hsk_addr_is_rfc4843(addr))
    return false;

  if (hsk_addr_is_local(addr))
    return false;

  return true;
}

void
hsk_addr_print(const hsk_addr_t *addr, const char *prefix) {
  assert(addr);

  char host[HSK_MAX_HOST];
  assert(hsk_addr_to_string(addr, host, HSK_MAX_HOST, HSK_BRONTIDE_PORT));

  printf("%saddr\n", prefix);
  printf("%s  type=%d\n", prefix, addr->type);
  printf("%s  host=%s\n", prefix, host);
}

void
hsk_netaddr_init(hsk_netaddr_t *na) {
  if (na == NULL)
    return;
  na->time = 0;
  na->services = 0;
  hsk_addr_init(&na->addr);
}

bool
hsk_netaddr_read(uint8_t **data, size_t *data_len, hsk_netaddr_t *na) {
  if (!read_u64(data, data_len, &na->time))
    return false;

  if (!read_u64(data, data_len, &na->services))
    return false;

  if (!read_u8(data, data_len, &na->addr.type))
    return false;

  if (!read_bytes(data, data_len, na->addr.ip, 36))
    return false;

  // Make sure we ignore trailing bytes
  // if the address is an IP address.
  if (na->addr.type == 0)
    memset(&na->addr.ip[16], 0x00, 20);

  if (!read_u16(data, data_len, &na->addr.port))
    return false;

  if (!read_bytes(data, data_len, na->addr.key, 33))
    return false;

  return true;
}

int
hsk_netaddr_write(const hsk_netaddr_t *na, uint8_t **data) {
  int s = 0;
  s += write_u64(data, na->time);
  s += write_u64(data, na->services);
  s += write_u8(data, na->addr.type);
  s += write_bytes(data, na->addr.ip, 36);
  s += write_u16(data, na->addr.port);
  s += write_bytes(data, na->addr.key, 33);
  return s;
}
