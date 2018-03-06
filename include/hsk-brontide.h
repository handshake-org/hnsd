#ifndef _HSK_BRONTIDE_H
#define _HSK_BRONTIDE_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "hsk-aead.h"
#include "hsk-hash.h"
#include "hsk-ec.h"

typedef struct hsk_cs_s {
  uint32_t nonce;
  uint8_t secret_key[32];
  uint8_t iv[12];
  uint8_t salt[32];
  uint8_t tag[16];
  hsk_aead_t cipher;
} hsk_cs_t;

typedef void (*hsk_brontide_connect_cb)(
  void *arg
);

typedef int32_t (*hsk_brontide_write_cb)(
  void *arg,
  uint8_t *data,
  size_t data_len,
  bool is_heap
);

typedef void (*hsk_brontide_read_cb)(
  void *arg,
  uint8_t *data,
  size_t data_len
);

typedef struct hsk_brontide_s {
  // Cipher state
  hsk_cs_t cs;

  // Symmetric state
  uint8_t chaining_key[32];
  uint8_t temp_key[32];
  uint8_t handshake_digest[32];

  // Handshake state
  hsk_ec_t *ec;
  bool initiator;
  uint8_t local_static[32];
  uint8_t local_ephemeral[32];
  uint8_t remote_static[33];
  uint8_t remote_ephemeral[33];

  // Brontide
  hsk_cs_t send_cipher;
  hsk_cs_t recv_cipher;

  // Net
  hsk_brontide_connect_cb connect_cb;
  void *connect_arg;
  hsk_brontide_write_cb write_cb;
  void *write_arg;
  hsk_brontide_read_cb read_cb;
  void *read_arg;

  int32_t state;
  bool has_size;
  uint8_t *msg;
  size_t msg_pos;
  size_t msg_len;
} hsk_brontide_t;

void
hsk_cs_init(hsk_cs_t *cs);

void
hsk_cs_update(hsk_cs_t *cs);

void
hsk_cs_init_key(hsk_cs_t *cs, uint8_t *key);

void
hsk_cs_init_saltkey(hsk_cs_t *cs, uint8_t *salt, uint8_t *key);

void
hsk_cs_rotate_key(hsk_cs_t *cs);

void
hsk_cs_encrypt(
  hsk_cs_t *cs,
  uint8_t *ad,
  uint8_t *in,
  uint8_t *out,
  size_t len
);

void
hsk_cs_decrypt(
  hsk_cs_t *cs,
  uint8_t *ad,
  uint8_t *in,
  uint8_t *out,
  size_t len
);

bool
hsk_cs_verify(hsk_cs_t *cs, uint8_t *tag);

void
hsk_brontide_init(hsk_brontide_t *b, hsk_ec_t *ec);

void
hsk_brontide_uninit(hsk_brontide_t *b);

/*
 * Symmetric State
 */

void
hsk_brontide_init_sym(hsk_brontide_t *b, const char *proto_name);

void
hsk_brontide_mix_key(hsk_brontide_t *b, uint8_t *in);

void
hsk_brontide_mix_hash(hsk_brontide_t *b, uint8_t *data, size_t data_len);

void
hsk_brontide_encrypt(hsk_brontide_t *b, uint8_t *in, uint8_t *out, size_t len);

void
hsk_brontide_decrypt(
  hsk_brontide_t *b,
  uint8_t *in,
  uint8_t *out,
  size_t len,
  uint8_t *tag
);

void
hsk_brontide_init_state(
  hsk_brontide_t *b,
  bool initiator,
  const char *prologue,
  uint8_t *local_pub,
  uint8_t *remote_pub
);

void
hsk_brontide_init_brontide(
  hsk_brontide_t *b,
  bool initiator,
  uint8_t *local_pub,
  uint8_t *remote_pub
);

void
hsk_brontide_destroy(hsk_brontide_t *b);

void
hsk_brontide_gen_act_one(hsk_brontide_t *b, uint8_t *act1);

bool
hsk_brontide_recv_act_one(hsk_brontide_t *b, uint8_t *act1);

void
hsk_brontide_gen_act_two(hsk_brontide_t *b, uint8_t *act2);

bool
hsk_brontide_recv_act_two(hsk_brontide_t *b, uint8_t *act2);

void
hsk_brontide_gen_act_three(hsk_brontide_t *b, uint8_t *act3);

bool
hsk_brontide_recv_act_three(hsk_brontide_t *b, uint8_t *act3);

void
hsk_brontide_split(hsk_brontide_t *b);

int32_t
hsk_brontide_accept(hsk_brontide_t *b, uint8_t *our_key);

int32_t
hsk_brontide_connect(hsk_brontide_t *b, uint8_t *our_key, uint8_t *their_key);

int32_t
hsk_brontide_on_connect(hsk_brontide_t *b);

int32_t
hsk_brontide_write(hsk_brontide_t *b, uint8_t *data, size_t data_len);

int32_t
hsk_brontide_on_read(hsk_brontide_t *b, uint8_t *data, size_t data_len);

int32_t
hsk_brontide_parse(
  hsk_brontide_t *b,
  uint8_t *data,
  size_t data_len,
  size_t *msg_len
);
#endif
