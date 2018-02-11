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

#include "hsk.h"
#include "blake2b.h"

static inline uint8_t
to_nibble(char s) {
  if (s >= '0' && s <= '9')
    return s - '0';

  if (s >= 'A' && s <= 'F')
    return (s - 'A') + 0x0a;

  if (s >= 'a' && s <= 'f')
    return (s - 'a') + 0x0a;

  return 0;
}

static inline char
to_char(uint8_t n) {
  if (n >= 0x00 && n <= 0x09)
    return n + '0';

  if (n >= 0x0a && n <= 0x0f)
    return (n - 0x0a) + 'a';

  return '0';
}

static uint8_t *
parse_hex(char *str, size_t *datalen) {
  if (str == NULL)
    return NULL;

  if (datalen)
    *datalen = 0;

  size_t size = strlen(str) >> 1;
  uint8_t *data = malloc(size);

  if (data == NULL)
    return NULL;

  char *s = str;
  int32_t i;

  for (i = 0; i < size; i++) {
    data[i] = to_nibble(*s) << 4;
    s++;
    data[i] |= to_nibble(*s);
    s++;
  }

  if (datalen)
    *datalen = size;

  return data;
}

static char *
to_hex(uint8_t *data, size_t datalen) {
  if (data == NULL)
    return NULL;

  size_t size = datalen << 1;
  char *str = malloc(size + 1);

  if (str == NULL)
    return NULL;

  int32_t i;
  int32_t j = 0;

  for (i = 0; i < size; i++) {
    if (i & 1)
      str[i] = to_char(data[j++] & 15);
    else
      str[i] = to_char(data[j] >> 4);
  }

  str[i] = '\0';

  return str;
}

int32_t
main(int32_t argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Bad args.");
    return 1;
  }

  argv += 1;

  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));

  hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_CANONNAME;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;

  struct addrinfo* result;
  struct addrinfo* res;
  int32_t rc;

  /* resolve the domain name into a list of addresses */
  rc = hsk_getaddrinfo(*argv, NULL, &hints, &result);

  if (rc != 0) {
    if (rc == EAI_SYSTEM) {
      perror("getaddrinfo");
    } else {
      fprintf(stderr, "error in getaddrinfo: %s\n", gai_strerror(rc));
    }
    exit(EXIT_FAILURE);
  }

  /* loop over all returned results and do inverse lookup */
  for (res = result; res != NULL; res = res->ai_next) {
    if (res->ai_addr->sa_family == AF_INET) {
      char ip[16];
      struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
      inet_ntop(AF_INET, &sa->sin_addr, (char *)ip, sizeof(ip));
      printf("name: %s, ipv4: %s\n", res->ai_canonname, ip);
    } else if (res->ai_addr->sa_family == AF_INET6) {
      char ip[256];
      struct sockaddr_in6 *sa = (struct sockaddr_in6 *)res->ai_addr;
      inet_ntop(AF_INET6, &sa->sin6_addr, (char *)ip, sizeof(ip));
      printf("name: %s, ipv6: %s\n", res->ai_canonname, ip);
    }
  }

  hsk_freeaddrinfo(result);

  if (hsk_is_sld(*argv)) {
    hsk_proof_t *proof;
    rc = hsk_get_proof(*argv, &proof);

    if (rc != HSK_SUCCESS) {
      fprintf(stderr, "error in hsk_getproof: %d\n", rc);
      exit(EXIT_FAILURE);
    }

    char *root_hex = "6fb2f647cdaa164081668c8f2a3fdcf2032efff903d1f69e42aff433105985de";
    uint8_t *root = parse_hex(root_hex, NULL);
    assert(root != NULL);

    char *key_hex = "4b2255c03411251d078e57d2f38146a4ebfa8c056b217aa9187decb821abdf2e";
    uint8_t *key = parse_hex(key_hex, NULL);
    assert(key != NULL);

    uint8_t *data;
    size_t data_len;
    int32_t rc = hsk_verify_name(root, hsk_to_tld(*argv), proof->nodes, &data, &data_len);
    //int32_t rc = hsk_verify_proof(root, key, proof->nodes, &data, &data_len);
    assert(data != NULL);

    printf("%d\n", rc);
    printf("%s\n", to_hex(data, data_len));

    uint8_t hash[32];
    blake2b_ctx ctx;

    assert(blake2b_init(&ctx, 32) >= 0);
    blake2b_update(&ctx, proof->data, proof->data_len);
    blake2b_final(&ctx, hash, 32);

    if (memcmp(hash, data, 32) != 0) {
      fprintf(stderr, "hashes not equal.\n");
      exit(EXIT_FAILURE);
    }

    hsk_resource_t *res;
    if (!hsk_decode_resource(proof->data, proof->data_len, &res)) {
      fprintf(stderr, "error in hsk_parse_resource\n");
      exit(EXIT_FAILURE);
    }
  }
}
