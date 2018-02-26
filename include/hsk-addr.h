#ifndef _HSK_ADDR_H
#define _HSK_ADDR_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

typedef struct hsk_addr_s {
  int32_t af;
  uint8_t ip[16];
  uint16_t port;
} hsk_addr_t;

void
hsk_addr_get(int32_t af, uint8_t *ip, uint16_t port, hsk_addr_t *addr);

uint32_t
hsk_addr_hash(void *key);

bool
hsk_addr_equal(void *a, void *b);
#endif
