#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "hsk-addr.h"

void
hsk_addr_get(int32_t af, uint8_t *ip, uint16_t port, hsk_addr_t *addr) {
  if (af == AF_INET) {
    addr->af = AF_INET;
    memcpy(addr->ip, (void *)ip, 4);
    addr->port = port;
  } else if (af == AF_INET6) {
    addr->af = AF_INET6;
    memcpy(addr->ip, (void *)ip, 16);
    addr->port = port;
  } else {
    assert(false);
  }
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
  uint32_t hash = (uint32_t)addr->af;

  if (addr->af == AF_INET) {
    hash = hsk_hash_data(hash, (uint8_t *)&addr->ip, 4);
    hash = hsk_hash_data(hash, (uint8_t *)&addr->port, 2);
  } else if (addr->af == AF_INET6) {
    hash = hsk_hash_data(hash, (uint8_t *)&addr->ip, 16);
    hash = hsk_hash_data(hash, (uint8_t *)&addr->port, 2);
  } else {
    assert(false);
  }

  return hash;
}

bool
hsk_addr_equal(void *a, void *b) {
  hsk_addr_t *x = (hsk_addr_t *)a;
  hsk_addr_t *y = (hsk_addr_t *)b;

  if (x->af != y->af)
    return false;

  if (x->af == AF_INET) {
    if (memcmp((void *)&x->ip, (void *)&y->ip, 4) != 0)
      return false;
  } else if (x->af == AF_INET6) {
    if (memcmp((void *)&x->ip, (void *)&y->ip, 16) != 0)
      return false;
  } else {
    assert(false);
  }

  if (x->port != y->port)
    return false;

  return true;
}
