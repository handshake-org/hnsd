#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "addr.h"
#include "bio.h"
#include "header.h"
#include "msg.h"
#include "proof.h"
#include "utils.h"

bool
hsk_version_msg_read(uint8_t **data, size_t *data_len, hsk_version_msg_t *msg) {
  if (!read_u32(data, data_len, &msg->version))
    return false;

  if (!read_u64(data, data_len, &msg->services))
    return false;

  if (!read_u64(data, data_len, &msg->time))
    return false;

  if (!hsk_netaddr_read(data, data_len, &msg->remote))
    return false;

  if (!read_u64(data, data_len, &msg->nonce))
    return false;

  uint8_t size;
  if (!read_u8(data, data_len, &size))
    return false;

  if (!read_ascii(data, data_len, msg->agent, (size_t)size))
    return false;

  if (!read_u32(data, data_len, &msg->height))
    return false;

  uint8_t no_relay;
  if (!read_u8(data, data_len, &no_relay))
    return false;

  msg->no_relay = no_relay == 1;

  return true;
}

int
hsk_version_msg_write(hsk_version_msg_t *msg, uint8_t **data) {
  int s = 0;
  s += write_u32(data, msg->version);
  s += write_u64(data, msg->services);
  s += write_u64(data, msg->time);
  s += hsk_netaddr_write(&msg->remote, data);
  s += write_u64(data, msg->nonce);
  size_t size = strlen(msg->agent);
  s += write_u8(data, size);
  s += write_bytes(data, (uint8_t *)msg->agent, size);
  s += write_u32(data, msg->height);
  s += write_u8(data, msg->no_relay ? 1 : 0);
  return s;
}

void
hsk_version_msg_print(const hsk_version_msg_t *msg, const char *prefix) {
  assert(msg);

  char remote[HSK_MAX_HOST];

  assert(hsk_addr_to_string(&msg->remote.addr, remote, HSK_MAX_HOST, 1));

  printf("%sversion msg\n", prefix);
  printf("%s  version=%d\n", prefix, msg->version);
  printf("%s  services=%lu\n", prefix, msg->services);
  printf("%s  time=%lu\n", prefix, msg->time);
  printf("%s  remote=%s\n", prefix, remote);
  printf("%s  nonce=%lu\n", prefix, msg->nonce);
  printf("%s  agent=%s\n", prefix, msg->agent);
  printf("%s  height=%d\n", prefix, msg->height);
  printf("%s  no_relay=%d\n", prefix, (int)msg->no_relay);
}

bool
hsk_verack_msg_read(uint8_t **data, size_t *data_len, hsk_verack_msg_t *msg) {
  return true;
}

int
hsk_verack_msg_write(const hsk_verack_msg_t *msg, uint8_t **data) {
  return 0;
}

bool
hsk_ping_msg_read(uint8_t **data, size_t *data_len, hsk_ping_msg_t *msg) {
  if (!read_u64(data, data_len, &msg->nonce))
    return false;
  return true;
}

int
hsk_ping_msg_write(const hsk_ping_msg_t *msg, uint8_t **data) {
  int s = 0;
  s += write_u64(data, msg->nonce);
  return s;
}

bool
hsk_pong_msg_read(uint8_t **data, size_t *data_len, hsk_pong_msg_t *msg) {
  if (!read_u64(data, data_len, &msg->nonce))
    return false;
  return true;
}

int
hsk_pong_msg_write(const hsk_pong_msg_t *msg, uint8_t **data) {
  int s = 0;
  s += write_u64(data, msg->nonce);
  return s;
}

bool
hsk_getaddr_msg_read(uint8_t **data, size_t *data_len, hsk_getaddr_msg_t *msg) {
  return true;
}

int
hsk_getaddr_msg_write(const hsk_getaddr_msg_t *msg, uint8_t **data) {
  return 0;
}

bool
hsk_addr_msg_read(uint8_t **data, size_t *data_len, hsk_addr_msg_t *msg) {
  if (!read_varsize(data, data_len, &msg->addr_count))
    return false;

  if (msg->addr_count > 1000)
    return false;

  int i;

  for (i = 0; i < msg->addr_count; i++) {
    if (!hsk_netaddr_read(data, data_len, &msg->addrs[i]))
      return false;
  }

  return true;
}

int
hsk_addr_msg_write(const hsk_addr_msg_t *msg, uint8_t **data) {
  int s = 0;

  s += write_varsize(data, msg->addr_count);

  int i;

  for (i = 0; i < msg->addr_count; i++)
    s += hsk_netaddr_write(&msg->addrs[i], data);

  return s;
}

bool
hsk_getheaders_msg_read(uint8_t **data, size_t *data_len, hsk_getheaders_msg_t *msg) {
  if (!read_varsize(data, data_len, &msg->hash_count))
    return false;

  if (msg->hash_count > 64)
    return false;

  int i;

  for (i = 0; i < msg->hash_count; i++) {
    if (!read_bytes(data, data_len, msg->hashes[i], 32))
      return false;
  }

  if (!read_bytes(data, data_len, msg->stop, 32))
    return false;

  return true;
}

int
hsk_getheaders_msg_write(const hsk_getheaders_msg_t *msg, uint8_t **data) {
  int s = 0;

  s += write_varsize(data, msg->hash_count);

  int i;

  for (i = 0; i < msg->hash_count; i++)
    s += write_bytes(data, msg->hashes[i], 32);

  s += write_bytes(data, msg->stop, 32);

  return s;
}

bool
hsk_headers_msg_read(uint8_t **data, size_t *data_len, hsk_headers_msg_t *msg) {
  if (!read_varsize(data, data_len, &msg->header_count))
    return false;

  if (msg->header_count > 2000)
    return false;

  hsk_header_t *tail = NULL;
  int i;

  for (i = 0; i < msg->header_count; i++) {
    hsk_header_t *h = hsk_header_alloc();

    if (h == NULL)
      goto fail;

    if (!hsk_header_read(data, data_len, h))
      goto fail;

    if (msg->headers == NULL)
      msg->headers = h;

    if (tail)
      tail->next = h;

    tail = h;
  }

  return true;

fail: ;
  hsk_header_t *c, *n;
  for (c = msg->headers; c; c = n) {
    n = c->next;
    free(c);
  }
  return false;
}

int
hsk_headers_msg_write(const hsk_headers_msg_t *msg, uint8_t **data) {
  int s = 0;

  s += write_varsize(data, msg->header_count);

  hsk_header_t *c;

  for (c = msg->headers; c; c = c->next)
    s += hsk_header_write(c, data);

  return s;
}

bool
hsk_sendheaders_msg_read(
  uint8_t **data,
  size_t *data_len,
  hsk_sendheaders_msg_t *msg
) {
  return true;
}

int
hsk_sendheaders_msg_write(const hsk_sendheaders_msg_t *msg, uint8_t **data) {
  return 0;
}

bool
hsk_getproof_msg_read(
  uint8_t **data,
  size_t *data_len,
  hsk_getproof_msg_t *msg
) {
  if (!read_bytes(data, data_len, msg->root, 32))
    return false;

  if (!read_bytes(data, data_len, msg->key, 32))
    return false;

  return true;
}

int
hsk_getproof_msg_write(const hsk_getproof_msg_t *msg, uint8_t **data) {
  int s = 0;
  s += write_bytes(data, msg->root, 32);
  s += write_bytes(data, msg->key, 32);
  return s;
}

bool
hsk_proof_msg_read(uint8_t **data, size_t *data_len, hsk_proof_msg_t *msg) {
  if (!read_bytes(data, data_len, msg->root, 32))
    return false;

  if (!read_bytes(data, data_len, msg->key, 32))
    return false;

  if (!hsk_proof_read(data, data_len, &msg->proof))
    return false;

  return true;
}

int
hsk_proof_msg_write(const hsk_proof_msg_t *msg, uint8_t **data) {
  int s = 0;

  s += write_bytes(data, msg->root, 32);
  s += write_bytes(data, msg->key, 32);
  // XXX

  return s;
}

uint8_t
hsk_msg_cmd(const char *cmd) {
  if (strcmp(cmd, "version") == 0)
    return HSK_MSG_VERSION;

  if (strcmp(cmd, "verack") == 0)
    return HSK_MSG_VERACK;

  if (strcmp(cmd, "ping") == 0)
    return HSK_MSG_PING;

  if (strcmp(cmd, "pong") == 0)
    return HSK_MSG_PONG;

  if (strcmp(cmd, "getaddr") == 0)
    return HSK_MSG_GETADDR;

  if (strcmp(cmd, "addr") == 0)
    return HSK_MSG_ADDR;

  if (strcmp(cmd, "getheaders") == 0)
    return HSK_MSG_GETHEADERS;

  if (strcmp(cmd, "headers") == 0)
    return HSK_MSG_HEADERS;

  if (strcmp(cmd, "sendheaders") == 0)
    return HSK_MSG_SENDHEADERS;

  if (strcmp(cmd, "getproof") == 0)
    return HSK_MSG_GETPROOF;

  if (strcmp(cmd, "proof") == 0)
    return HSK_MSG_PROOF;

  return HSK_MSG_UNKNOWN;
}

const char *
hsk_msg_str(uint8_t cmd) {
  switch (cmd) {
    case HSK_MSG_VERSION: {
      return "version";
    }
    case HSK_MSG_VERACK: {
      return "verack";
    }
    case HSK_MSG_PING: {
      return "ping";
    }
    case HSK_MSG_PONG: {
      return "pong";
    }
    case HSK_MSG_GETADDR: {
      return "getaddr";
    }
    case HSK_MSG_ADDR: {
      return "addr";
    }
    case HSK_MSG_GETHEADERS: {
      return "getheaders";
    }
    case HSK_MSG_HEADERS: {
      return "headers";
    }
    case HSK_MSG_SENDHEADERS: {
      return "sendheaders";
    }
    case HSK_MSG_GETPROOF: {
      return "getproof";
    }
    case HSK_MSG_PROOF: {
      return "proof";
    }
    default: {
      return "unknown";
    }
  }
}

void
hsk_msg_init(hsk_msg_t *msg) {
  if (msg == NULL)
    return;

  switch (msg->cmd) {
    case HSK_MSG_VERSION: {
      hsk_version_msg_t *m = (hsk_version_msg_t *)msg;
      m->cmd = HSK_MSG_VERSION;
      m->version = 0;
      m->services = 0;
      m->time = 0;
      hsk_netaddr_init(&m->remote);
      m->nonce = 0;
      memset(m->agent, 0, 256);
      m->height = 0;
      m->no_relay = false;
      break;
    }
    case HSK_MSG_VERACK: {
      hsk_verack_msg_t *m = (hsk_verack_msg_t *)msg;
      m->cmd = HSK_MSG_VERACK;
      break;
    }
    case HSK_MSG_PING: {
      hsk_ping_msg_t *m = (hsk_ping_msg_t *)msg;
      m->cmd = HSK_MSG_PING;
      m->nonce = 0;
      break;
    }
    case HSK_MSG_PONG: {
      hsk_pong_msg_t *m = (hsk_pong_msg_t *)msg;
      m->cmd = HSK_MSG_PONG;
      m->nonce = 0;
      break;
    }
    case HSK_MSG_GETADDR: {
      hsk_getaddr_msg_t *m = (hsk_getaddr_msg_t *)msg;
      m->cmd = HSK_MSG_GETADDR;
      break;
    }
    case HSK_MSG_ADDR: {
      hsk_addr_msg_t *m = (hsk_addr_msg_t *)msg;
      m->cmd = HSK_MSG_ADDR;
      m->addr_count = 0;
      int i;
      for (i = 0; i < 1000; i++)
        hsk_netaddr_init(&m->addrs[i]);
      break;
    }
    case HSK_MSG_GETHEADERS: {
      hsk_getheaders_msg_t *m = (hsk_getheaders_msg_t *)msg;
      m->cmd = HSK_MSG_GETHEADERS;
      int i;
      for (i = 0; i < 64; i++)
        memset(m->hashes[i], 0, 32);
      memset(m->stop, 0, 32);
      break;
    }
    case HSK_MSG_HEADERS: {
      hsk_headers_msg_t *m = (hsk_headers_msg_t *)msg;
      m->cmd = HSK_MSG_HEADERS;
      m->header_count = 0;
      m->headers = NULL;
      break;
    }
    case HSK_MSG_SENDHEADERS: {
      hsk_sendheaders_msg_t *m = (hsk_sendheaders_msg_t *)msg;
      m->cmd = HSK_MSG_SENDHEADERS;
      break;
    }
    case HSK_MSG_GETPROOF: {
      hsk_getproof_msg_t *m = (hsk_getproof_msg_t *)msg;
      m->cmd = HSK_MSG_GETPROOF;
      memset(m->root, 0, 32);
      memset(m->key, 0, 32);
      break;
    }
    case HSK_MSG_PROOF: {
      hsk_proof_msg_t *m = (hsk_proof_msg_t *)msg;
      m->cmd = HSK_MSG_PROOF;
      memset(m->root, 0, 32);
      memset(m->key, 0, 32);
      hsk_proof_init(&m->proof);
      break;
    }
  }
}

hsk_msg_t *
hsk_msg_alloc(uint8_t cmd) {
  hsk_msg_t *msg = NULL;

  switch (cmd) {
    case HSK_MSG_VERSION: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_version_msg_t));
      break;
    }
    case HSK_MSG_VERACK: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_verack_msg_t));
      break;
    }
    case HSK_MSG_PING: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_ping_msg_t));
      break;
    }
    case HSK_MSG_PONG: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_pong_msg_t));
      break;
    }
    case HSK_MSG_GETADDR: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_getaddr_msg_t));
      break;
    }
    case HSK_MSG_ADDR: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_addr_msg_t));
      break;
    }
    case HSK_MSG_GETHEADERS: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_getheaders_msg_t));
      break;
    }
    case HSK_MSG_HEADERS: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_headers_msg_t));
      break;
    }
    case HSK_MSG_SENDHEADERS: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_sendheaders_msg_t));
      break;
    }
    case HSK_MSG_GETPROOF: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_getproof_msg_t));
      break;
    }
    case HSK_MSG_PROOF: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_proof_msg_t));
      break;
    }
  }

  if (msg)
    msg->cmd = cmd;

  hsk_msg_init(msg);

  return msg;
}

void
hsk_msg_free(hsk_msg_t *msg) {
  if (msg == NULL)
    return;

  switch (msg->cmd) {
    case HSK_MSG_VERSION: {
      hsk_version_msg_t *m = (hsk_version_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_VERACK: {
      hsk_verack_msg_t *m = (hsk_verack_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_PING: {
      hsk_ping_msg_t *m = (hsk_ping_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_PONG: {
      hsk_pong_msg_t *m = (hsk_pong_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_GETADDR: {
      hsk_getaddr_msg_t *m = (hsk_getaddr_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_ADDR: {
      hsk_addr_msg_t *m = (hsk_addr_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_GETHEADERS: {
      hsk_getheaders_msg_t *m = (hsk_getheaders_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_HEADERS: {
      hsk_headers_msg_t *m = (hsk_headers_msg_t *)msg;
      hsk_header_t *c, *n;
      for (c = m->headers; c; c = n) {
        n = c->next;
        free(c);
      }
      free(m);
      break;
    }
    case HSK_MSG_SENDHEADERS: {
      hsk_sendheaders_msg_t *m = (hsk_sendheaders_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_GETPROOF: {
      hsk_getproof_msg_t *m = (hsk_getproof_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_PROOF: {
      hsk_proof_msg_t *m = (hsk_proof_msg_t *)msg;
      hsk_proof_uninit(&m->proof);
      free(m);
      break;
    }
  }
}

bool
hsk_msg_read(uint8_t **data, size_t *data_len, hsk_msg_t *msg) {
  switch (msg->cmd) {
    case HSK_MSG_VERSION: {
      return hsk_version_msg_read(data, data_len, (hsk_version_msg_t *)msg);
    }
    case HSK_MSG_VERACK: {
      return hsk_verack_msg_read(data, data_len, (hsk_verack_msg_t *)msg);
    }
    case HSK_MSG_PING: {
      return hsk_ping_msg_read(data, data_len, (hsk_ping_msg_t *)msg);
    }
    case HSK_MSG_PONG: {
      return hsk_pong_msg_read(data, data_len, (hsk_pong_msg_t *)msg);
    }
    case HSK_MSG_GETADDR: {
      return hsk_getaddr_msg_read(data, data_len, (hsk_getaddr_msg_t *)msg);
    }
    case HSK_MSG_ADDR: {
      return hsk_addr_msg_read(data, data_len, (hsk_addr_msg_t *)msg);
    }
    case HSK_MSG_GETHEADERS: {
      return hsk_getheaders_msg_read(data, data_len, (hsk_getheaders_msg_t *)msg);
    }
    case HSK_MSG_HEADERS: {
      return hsk_headers_msg_read(data, data_len, (hsk_headers_msg_t *)msg);
    }
    case HSK_MSG_SENDHEADERS: {
      return hsk_sendheaders_msg_read(data, data_len, (hsk_sendheaders_msg_t *)msg);
    }
    case HSK_MSG_GETPROOF: {
      return hsk_getproof_msg_read(data, data_len, (hsk_getproof_msg_t *)msg);
    }
    case HSK_MSG_PROOF: {
      return hsk_proof_msg_read(data, data_len, (hsk_proof_msg_t *)msg);
    }
    default: {
      return false;
    }
  }
}

int
hsk_msg_write(const hsk_msg_t *msg, uint8_t **data) {
  switch (msg->cmd) {
    case HSK_MSG_VERSION: {
      return hsk_version_msg_write((hsk_version_msg_t *)msg, data);
    }
    case HSK_MSG_VERACK: {
      return hsk_verack_msg_write((hsk_verack_msg_t *)msg, data);
    }
    case HSK_MSG_PING: {
      return hsk_ping_msg_write((hsk_ping_msg_t *)msg, data);
    }
    case HSK_MSG_PONG: {
      return hsk_pong_msg_write((hsk_pong_msg_t *)msg, data);
    }
    case HSK_MSG_GETADDR: {
      return hsk_getaddr_msg_write((hsk_getaddr_msg_t *)msg, data);
    }
    case HSK_MSG_ADDR: {
      return hsk_addr_msg_write((hsk_addr_msg_t *)msg, data);
    }
    case HSK_MSG_GETHEADERS: {
      return hsk_getheaders_msg_write((hsk_getheaders_msg_t *)msg, data);
    }
    case HSK_MSG_HEADERS: {
      return hsk_headers_msg_write((hsk_headers_msg_t *)msg, data);
    }
    case HSK_MSG_SENDHEADERS: {
      return hsk_sendheaders_msg_write((hsk_sendheaders_msg_t *)msg, data);
    }
    case HSK_MSG_GETPROOF: {
      return hsk_getproof_msg_write((hsk_getproof_msg_t *)msg, data);
    }
    case HSK_MSG_PROOF: {
      return hsk_proof_msg_write((hsk_proof_msg_t *)msg, data);
    }
    default: {
      return -1;
    }
  }
}

bool
hsk_msg_decode(const uint8_t *data, size_t data_len, hsk_msg_t *msg) {
  return hsk_msg_read((uint8_t **)&data, &data_len, msg);
}

int
hsk_msg_encode(const hsk_msg_t *msg, uint8_t *data) {
  return hsk_msg_write(msg, &data);
}

int
hsk_msg_size(const hsk_msg_t *msg) {
  return hsk_msg_write(msg, NULL);
}
