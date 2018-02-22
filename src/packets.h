#ifndef _HSK_PACKETS_H
#define _HSK_PACKETS_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "hsk-header.h"
#include "hsk-proof.h"

#define MSG_VERSION 0
#define MSG_VERACK 1
#define MSG_PING 2
#define MSG_PONG 3
#define MSG_GETADDR 4
#define MSG_ADDR 5
#define MSG_GETHEADERS 10
#define MSG_HEADERS 11
#define MSG_SENDHEADERS 12
#define MSG_GETPROOF 31
#define MSG_PROOF 32
#define MSG_UNKNOWN 255

// bidirectional
typedef struct {
  uint64_t time;
  uint64_t services;
  uint8_t type;
  uint8_t addr[36];
  uint16_t port;
} hsk_addr_t;

typedef struct {
  uint8_t cmd;
} hsk_msg_t;

// bidirectional
typedef struct {
  uint8_t cmd; // 0
  uint32_t version;
  uint64_t services;
  uint64_t time;
  hsk_addr_t remote;
  hsk_addr_t local;
  uint64_t nonce;
  char agent[256];
  uint32_t height;
  uint8_t no_relay;
} hsk_version_msg_t;

// bidirectional
typedef struct {
  uint8_t cmd; // 1
} hsk_verack_msg_t;

// bidirectional
typedef struct {
  uint8_t cmd; // 2
  uint64_t nonce;
} hsk_ping_msg_t;

// bidirectional
typedef struct {
  uint8_t cmd; // 3
  uint64_t nonce;
} hsk_pong_msg_t;

// us
typedef struct {
  uint8_t cmd; // 4
} hsk_getaddr_msg_t;

// them
typedef struct {
  uint8_t cmd; // 5
  size_t addr_count;
  hsk_addr_t addrs[1000];
} hsk_addr_msg_t;

// us
typedef struct {
  uint8_t cmd; // 10
  size_t hash_count;
  uint8_t hashes[64][32];
  uint8_t stop[32];
} hsk_getheaders_msg_t;

// them
typedef struct {
  uint8_t cmd; // 11
  size_t header_count;
  hsk_header_t *headers;
} hsk_headers_msg_t;

// us
typedef struct {
  uint8_t cmd; // 12
} hsk_sendheaders_msg_t;

// us
typedef struct {
  uint8_t cmd; // 31
  uint8_t name_hash[32];
  uint8_t root[32];
} hsk_getproof_msg_t;

// them
typedef struct {
  uint8_t cmd; // 32
  uint8_t name_hash[32];
  uint8_t root[32];
  size_t node_count;
  hsk_raw_node_t *nodes;
  size_t data_len;
  uint8_t data[512];
} hsk_proof_msg_t;

uint8_t
hsk_msg_cmd(char *cmd);

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

int32_t
hsk_msg_write(hsk_msg_t *msg, uint8_t **data);

bool
hsk_msg_decode(uint8_t *data, size_t data_len, hsk_msg_t *msg);

int32_t
hsk_msg_encode(hsk_msg_t *msg, uint8_t *data);

int32_t
hsk_msg_size(hsk_msg_t *msg);
#endif
