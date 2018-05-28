#ifndef _HSK_MSG_H
#define _HSK_MSG_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "addr.h"
#include "header.h"
#include "proof.h"

#define HSK_MSG_VERSION 0
#define HSK_MSG_VERACK 1
#define HSK_MSG_PING 2
#define HSK_MSG_PONG 3
#define HSK_MSG_GETADDR 4
#define HSK_MSG_ADDR 5
#define HSK_MSG_GETHEADERS 10
#define HSK_MSG_HEADERS 11
#define HSK_MSG_SENDHEADERS 12
#define HSK_MSG_GETPROOF 26
#define HSK_MSG_PROOF 27
#define HSK_MSG_UNKNOWN 255

typedef struct {
  uint8_t cmd;
} hsk_msg_t;

typedef struct {
  uint8_t cmd;
  uint32_t version;
  uint64_t services;
  uint64_t time;
  hsk_netaddr_t remote;
  uint64_t nonce;
  char agent[256];
  uint32_t height;
  uint8_t no_relay;
} hsk_version_msg_t;

typedef struct {
  uint8_t cmd;
} hsk_verack_msg_t;

typedef struct {
  uint8_t cmd;
  uint64_t nonce;
} hsk_ping_msg_t;

typedef struct {
  uint8_t cmd;
  uint64_t nonce;
} hsk_pong_msg_t;

typedef struct {
  uint8_t cmd;
} hsk_getaddr_msg_t;

typedef struct {
  uint8_t cmd;
  size_t addr_count;
  hsk_netaddr_t addrs[1000];
} hsk_addr_msg_t;

typedef struct {
  uint8_t cmd;
  size_t hash_count;
  uint8_t hashes[64][32];
  uint8_t stop[32];
} hsk_getheaders_msg_t;

typedef struct {
  uint8_t cmd;
  size_t header_count;
  hsk_header_t *headers;
} hsk_headers_msg_t;

typedef struct {
  uint8_t cmd;
} hsk_sendheaders_msg_t;

typedef struct {
  uint8_t cmd;
  uint8_t root[32];
  uint8_t key[20];
} hsk_getproof_msg_t;

typedef struct {
  uint8_t cmd;
  uint8_t root[32];
  uint8_t key[20];
  hsk_proof_t proof;
} hsk_proof_msg_t;

uint8_t
hsk_msg_cmd(const char *cmd);

const char *
hsk_msg_str(uint8_t cmd);

void
hsk_msg_init(hsk_msg_t *msg);

hsk_msg_t *
hsk_msg_alloc(uint8_t cmd);

void
hsk_msg_free(hsk_msg_t *msg);

bool
hsk_msg_read(uint8_t **data, size_t *data_len, hsk_msg_t *msg);

int
hsk_msg_write(const hsk_msg_t *msg, uint8_t **data);

bool
hsk_msg_decode(const uint8_t *data, size_t data_len, hsk_msg_t *msg);

int
hsk_msg_encode(const hsk_msg_t *msg, uint8_t *data);

int
hsk_msg_size(const hsk_msg_t *msg);
#endif
