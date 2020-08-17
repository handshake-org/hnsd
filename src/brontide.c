/**
 * Ported to C from the go-lang implementation (LND):
 *   Copyright (C) 2015-2017 The Lightning Network Developers
 *   https://github.com/lightningnetwork/lnd/blob/master/brontide/noise.go
 *   https://github.com/lightningnetwork/lnd/blob/master/brontide/noise_test.go
 */

#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "aead.h"
#include "bio.h"
#include "brontide.h"
#include "constants.h"
#include "ec.h"
#include "error.h"
#include "hash.h"
#include "sha256.h"
#include "utils.h"

static const char brontide_protocol_name[] =
  "Noise_XK_secp256k1_ChaChaPoly_SHA256+SVDW_Squared";

// Our primary difference from lightning:
// We use "hns" instead of "lightning".
static const char brontide_prologue[] = "hns";

#define BRONTIDE_ROTATION_INTERVAL 1000
#define BRONTIDE_VERSION 0

#define BRONTIDE_MAC_SIZE 16
#define BRONTIDE_LENGTH_SIZE 4
#define BRONTIDE_HEADER_SIZE 20

#define BRONTIDE_ACT_ONE_SIZE 80
#define BRONTIDE_ACT_TWO_SIZE 80
#define BRONTIDE_ACT_THREE_SIZE 65

#define BRONTIDE_ACT_NONE 0
#define BRONTIDE_ACT_ONE 1
#define BRONTIDE_ACT_TWO 2
#define BRONTIDE_ACT_THREE 3
#define BRONTIDE_ACT_DONE 4

#define BRONTIDE_MAX_MESSAGE (HSK_MAX_MESSAGE + 9)

/*
 * Cipher State
 */

void
hsk_cs_init(hsk_cs_t *cs) {
  cs->nonce = 0;
  memset(cs->iv, 0, 12);
  memset(cs->secret_key, 0, 32);
  memset(cs->salt, 0, 32);
  memset(cs->tag, 0, 16);
  hsk_aead_init(&cs->cipher);
}

void
hsk_cs_update(hsk_cs_t *cs) {
  uint8_t *buf = &cs->iv[4];
  write_u32(&buf, cs->nonce);
}

void
hsk_cs_init_key(hsk_cs_t *cs, const uint8_t *key) {
  memcpy(cs->secret_key, key, 32);
  cs->nonce = 0;
  hsk_cs_update(cs);
}

void
hsk_cs_init_saltkey(hsk_cs_t *cs, const uint8_t *salt, const uint8_t *key) {
  memcpy(cs->salt, salt, 32);
  hsk_cs_init_key(cs, key);
}

void
hsk_cs_rotate_key(hsk_cs_t *cs) {
  uint8_t *info = NULL;
  uint8_t *old_key = cs->secret_key;
  uint8_t h1[32];
  uint8_t h2[32];

  hsk_hash_hkdf(old_key, 32, cs->salt, 32, info, 0, h1, h2);

  memcpy(cs->salt, h1, 32);

  uint8_t *next_key = &h2[0];

  hsk_cs_init_key(cs, next_key);
}

void
hsk_cs_encrypt(
  hsk_cs_t *cs,
  const uint8_t *ad,
  const uint8_t *in,
  uint8_t *out,
  size_t len
) {
  hsk_aead_setup(&cs->cipher, cs->secret_key, cs->iv);

  if (ad)
    hsk_aead_aad(&cs->cipher, ad, 32);

  hsk_aead_encrypt(&cs->cipher, in, out, len);
  hsk_aead_final(&cs->cipher, cs->tag);

  cs->nonce += 1;
  hsk_cs_update(cs);

  if (cs->nonce == BRONTIDE_ROTATION_INTERVAL)
    hsk_cs_rotate_key(cs);
}

void
hsk_cs_decrypt(
  hsk_cs_t *cs,
  const uint8_t *ad,
  const uint8_t *in,
  uint8_t *out,
  size_t len
) {
  hsk_aead_setup(&cs->cipher, cs->secret_key, cs->iv);

  if (ad)
    hsk_aead_aad(&cs->cipher, ad, 32);

  hsk_aead_decrypt(&cs->cipher, in, out, len);
  hsk_aead_final(&cs->cipher, cs->tag);

  cs->nonce += 1;
  hsk_cs_update(cs);

  if (cs->nonce == BRONTIDE_ROTATION_INTERVAL)
    hsk_cs_rotate_key(cs);
}

bool
hsk_cs_verify(const hsk_cs_t *cs, const uint8_t *tag) {
  return hsk_aead_verify(cs->tag, tag);
}

/*
 * Brontide
 */

void
hsk_brontide_init(hsk_brontide_t *b, const hsk_ec_t *ec) {
  assert(b && ec);

  // Cipher State
  hsk_cs_init(&b->cs);

  // Symmetric State
  memset(b->chaining_key, 0, 32);
  memset(b->temp_key, 0, 32);
  memset(b->handshake_digest, 0, 32);

  // Handshake State
  b->ec = (hsk_ec_t *)ec;
  b->initiator = false;
  memset(b->local_static, 0, 32);
  memset(b->local_ephemeral, 0, 32);
  memset(b->remote_static, 0, 33);
  memset(b->remote_ephemeral, 0, 33);

  // Brontide
  hsk_cs_init(&b->send_cipher);
  hsk_cs_init(&b->recv_cipher);

  // Net
  b->connect_cb = NULL;
  b->connect_arg = NULL;
  b->write_cb = NULL;
  b->write_arg = NULL;
  b->read_cb = NULL;
  b->read_arg = NULL;

  b->state = BRONTIDE_ACT_NONE;
  b->has_size = false;
  b->msg = NULL;
  b->msg_pos = 0;
  b->msg_len = 0;
}

void
hsk_brontide_uninit(hsk_brontide_t *b) {
  assert(b);

  hsk_brontide_destroy(b);

  if (b->msg) {
    free(b->msg);
    b->msg = NULL;
  }
}

/*
 * Symmetric State
 */

void
hsk_brontide_init_sym(hsk_brontide_t *b, const char *proto_name) {
  uint8_t empty[32];

  memset(empty, 0, 32);

  hsk_hash_sha256(
    (uint8_t *)proto_name,
    strlen(proto_name),
    b->handshake_digest
  );

  memcpy(b->chaining_key, b->handshake_digest, 32);

  hsk_cs_init_key(&b->cs, empty);
}

void
hsk_brontide_mix_key(hsk_brontide_t *b, const uint8_t *in) {
  uint8_t *info = NULL;
  const uint8_t *secret = in;
  uint8_t *salt = b->chaining_key;

  hsk_hash_hkdf(secret, 32, salt, 32, info, 0, b->chaining_key, b->temp_key);

  hsk_cs_init_key(&b->cs, b->temp_key);
}

static void
hsk_brontide__mix_hash(
  hsk_brontide_t *b,
  const uint8_t *data,
  size_t data_len,
  const uint8_t *tag,
  uint8_t *hash
) {
  hsk_sha256_ctx ctx;
  hsk_sha256_init(&ctx);
  hsk_sha256_update(&ctx, b->handshake_digest, 32);
  hsk_sha256_update(&ctx, data, data_len);

  if (tag)
    hsk_sha256_update(&ctx, tag, 16);

  hsk_sha256_final(&ctx, hash);
}

void
hsk_brontide_mix_hash(hsk_brontide_t *b, const uint8_t *data, size_t data_len) {
  hsk_brontide__mix_hash(b, data, data_len, NULL, b->handshake_digest);
}

void
hsk_brontide_encrypt(
  hsk_brontide_t *b,
  const uint8_t *in,
  uint8_t *out,
  size_t len
) {
  hsk_cs_encrypt(&b->cs, b->handshake_digest, in, out, len);
  hsk_brontide__mix_hash(b, out, len, b->cs.tag, b->handshake_digest);
}

void
hsk_brontide_decrypt(
  hsk_brontide_t *b,
  const uint8_t *in,
  uint8_t *out,
  size_t len,
  const uint8_t *tag
) {
  assert(tag);
  uint8_t h[32];
  hsk_brontide__mix_hash(b, in, len, tag, h);
  hsk_cs_decrypt(&b->cs, b->handshake_digest, in, out, len);
  memcpy(b->handshake_digest, h, 32);
}

void
hsk_brontide_init_state(
  hsk_brontide_t *b,
  bool initiator,
  const char *prologue,
  const uint8_t *local_pub,
  const uint8_t *remote_pub
) {
  b->initiator = initiator;
  memcpy(b->local_static, local_pub, 32);

  if (remote_pub)
    memcpy(b->remote_static, remote_pub, 33);
  else
    memset(b->remote_static, 0, 33);

  hsk_brontide_init_sym(b, brontide_protocol_name);
  hsk_brontide_mix_hash(b, (const uint8_t *)prologue, strlen(prologue));

  if (initiator) {
    assert(remote_pub);
    hsk_brontide_mix_hash(b, remote_pub, 33);
  } else {
    uint8_t pub[33];
    assert(hsk_ec_create_pubkey(b->ec, local_pub, pub));
    hsk_brontide_mix_hash(b, pub, 33);
  }
}

void
hsk_brontide_init_brontide(
  hsk_brontide_t *b,
  bool initiator,
  const uint8_t *local_pub,
  const uint8_t *remote_pub
) {
  hsk_brontide_init_state(
    b,
    initiator,
    brontide_prologue,
    local_pub,
    remote_pub
  );
}

void
hsk_brontide_destroy(hsk_brontide_t *b) {
  b->state = BRONTIDE_ACT_NONE;
}

void
hsk_brontide_gen_act_one(hsk_brontide_t *b, uint8_t *act1) {
  // e
  assert(hsk_ec_create_privkey(b->ec, b->local_ephemeral));

  uint8_t ephemeral[33];
  assert(hsk_ec_create_pubkey(b->ec, b->local_ephemeral, ephemeral));

  uint8_t uniform[64];
  hsk_ec_pubkey_to_hash(b->ec, ephemeral, uniform);

  hsk_brontide_mix_hash(b, ephemeral, 33);

  // ec
  uint8_t s[32];
  assert(hsk_ec_ecdh(b->ec, b->remote_static, b->local_ephemeral, s));
  hsk_brontide_mix_key(b, s);

  hsk_brontide_encrypt(b, NULL, NULL, 0);

  memcpy(&act1[0], uniform, 64);
  memcpy(&act1[64], b->cs.tag, 16);
}

bool
hsk_brontide_recv_act_one(hsk_brontide_t *b, const uint8_t *act1) {
  const uint8_t *u = &act1[0];
  const uint8_t *p = &act1[64];

  uint8_t e[33];
  hsk_ec_pubkey_from_hash(b->ec, u, e);

  // e
  memcpy(b->remote_ephemeral, e, 33);
  hsk_brontide_mix_hash(b, b->remote_ephemeral, 33);

  // es
  uint8_t s[32];
  assert(hsk_ec_ecdh(b->ec, b->remote_ephemeral, b->local_static, s));
  hsk_brontide_mix_key(b, s);

  hsk_brontide_decrypt(b, NULL, NULL, 0, p);

  if (!hsk_cs_verify(&b->cs, p))
    return false;

  return true;
}

void
hsk_brontide_gen_act_two(hsk_brontide_t *b, uint8_t *act2) {
  // e
  assert(hsk_ec_create_privkey(b->ec, b->local_ephemeral));

  uint8_t ephemeral[33];
  assert(hsk_ec_create_pubkey(b->ec, b->local_ephemeral, ephemeral));

  uint8_t uniform[64];
  hsk_ec_pubkey_to_hash(b->ec, ephemeral, uniform);

  hsk_brontide_mix_hash(b, ephemeral, 33);

  // ee
  uint8_t s[32];
  assert(hsk_ec_ecdh(b->ec, b->remote_ephemeral, b->local_ephemeral, s));
  hsk_brontide_mix_key(b, s);

  hsk_brontide_encrypt(b, NULL, NULL, 0);

  memcpy(&act2[0], uniform, 64);
  memcpy(&act2[64], b->cs.tag, 16);
}

bool
hsk_brontide_recv_act_two(hsk_brontide_t *b, const uint8_t *act2) {
  const uint8_t *u = &act2[0];
  const uint8_t *p = &act2[64];

  uint8_t e[33];
  hsk_ec_pubkey_from_hash(b->ec, u, e);

  if (!hsk_ec_verify_pubkey(b->ec, e))
    return false;

  // e
  memcpy(b->remote_ephemeral, e, 33);
  hsk_brontide_mix_hash(b, b->remote_ephemeral, 33);

  // ee
  uint8_t s[32];
  assert(hsk_ec_ecdh(b->ec, b->remote_ephemeral, b->local_ephemeral, s));
  hsk_brontide_mix_key(b, s);

  hsk_brontide_decrypt(b, NULL, NULL, 0, p);

  if (!hsk_cs_verify(&b->cs, p))
    return false;

  return true;
}

void
hsk_brontide_gen_act_three(hsk_brontide_t *b, uint8_t *act3) {
  uint8_t our_pubkey[33];
  assert(hsk_ec_create_pubkey(b->ec, b->local_static, our_pubkey));
  hsk_brontide_encrypt(b, our_pubkey, our_pubkey, 33);
  uint8_t tag1[16];
  memcpy(tag1, b->cs.tag, 16);

  uint8_t s[32];
  assert(hsk_ec_ecdh(b->ec, b->remote_ephemeral, b->local_static, s));
  hsk_brontide_mix_key(b, s);

  hsk_brontide_encrypt(b, NULL, NULL, 0);
  uint8_t *tag2 = b->cs.tag;

  memcpy(&act3[0], our_pubkey, 33);
  memcpy(&act3[33], tag1, 16);
  memcpy(&act3[49], tag2, 16);

  hsk_brontide_split(b);
}

bool
hsk_brontide_recv_act_three(hsk_brontide_t *b, const uint8_t *act3) {
  const uint8_t *s1 = &act3[0];
  const uint8_t *p1 = &act3[33];

  const uint8_t *s2 = NULL;
  const uint8_t *p2 = &act3[49];

  uint8_t remote_pub[33];
  hsk_brontide_decrypt(b, s1, remote_pub, 33, p1);

  if (!hsk_cs_verify(&b->cs, p1))
    return false;

  memcpy(b->remote_static, remote_pub, 33);

  // se
  uint8_t se[32];
  assert(hsk_ec_ecdh(b->ec, b->remote_static, b->local_ephemeral, se));
  hsk_brontide_mix_key(b, se);

  hsk_brontide_decrypt(b, s2, NULL, 0, p2);

  if (!hsk_cs_verify(&b->cs, p2))
    return false;

  hsk_brontide_split(b);

  return true;
}

void
hsk_brontide_split(hsk_brontide_t *b) {
  uint8_t h1[32];
  uint8_t h2[32];

  hsk_hash_hkdf(NULL, 0, b->chaining_key, 32, NULL, 0, h1, h2);

  if (b->initiator) {
    uint8_t *send_key = &h1[0];
    hsk_cs_init_saltkey(&b->send_cipher, b->chaining_key, send_key);
    uint8_t *recv_key = &h2[0];
    hsk_cs_init_saltkey(&b->recv_cipher, b->chaining_key, recv_key);
  } else {
    uint8_t *recv_key = &h1[0];
    hsk_cs_init_saltkey(&b->recv_cipher, b->chaining_key, recv_key);
    uint8_t *send_key = &h2[0];
    hsk_cs_init_saltkey(&b->send_cipher, b->chaining_key, send_key);
  }
}

int
hsk_brontide_accept(hsk_brontide_t *b, const uint8_t *our_key) {
  hsk_brontide_init_brontide(b, false, our_key, NULL);
  return hsk_brontide_on_connect(b);
}

int
hsk_brontide_connect(
  hsk_brontide_t *b,
  const uint8_t *our_key,
  const uint8_t *their_key
) {
  hsk_brontide_init_brontide(b, true, our_key, their_key);
  return HSK_SUCCESS;
}

int
hsk_brontide_on_connect(hsk_brontide_t *b) {
  size_t size;

  assert(b->write_cb);

  if (b->initiator) {
    b->state = BRONTIDE_ACT_TWO;

    uint8_t act1[BRONTIDE_ACT_ONE_SIZE];

    hsk_brontide_gen_act_one(b, act1);

    int r = b->write_cb(b->write_arg, act1, BRONTIDE_ACT_ONE_SIZE, false);

    if (r != HSK_SUCCESS) {
      hsk_brontide_destroy(b);
      return r;
    }

    size = BRONTIDE_ACT_TWO_SIZE;
  } else {
    b->state = BRONTIDE_ACT_ONE;
    size = BRONTIDE_ACT_ONE_SIZE;
  }

  assert(size != 0);

  uint8_t *msg = realloc(b->msg, size);

  if (!msg)
    return HSK_ENOMEM;

  b->msg = msg;
  b->msg_pos = 0;
  b->msg_len = size;

  return HSK_SUCCESS;
}

int
hsk_brontide_write(hsk_brontide_t *b, uint8_t *data, size_t data_len) {
  assert(b->write_cb);

  int r = HSK_SUCCESS;

  if (b->state != BRONTIDE_ACT_DONE)
    goto done;

  uint8_t len[4];

  set_u32(&len[0], (uint32_t)data_len);

  hsk_cs_encrypt(&b->send_cipher, NULL, len, len, 4);

  r = b->write_cb(b->write_arg, len, 4, false);

  if (r != 0)
    goto done;

  r = b->write_cb(b->write_arg, b->send_cipher.tag, 16, false);

  if (r != 0)
    goto done;

  hsk_cs_encrypt(&b->send_cipher, NULL, data, data, data_len);

  r = b->write_cb(b->write_arg, data, data_len, true);

  if (r != 0)
    goto done;

  r = b->write_cb(b->write_arg, b->send_cipher.tag, 16, false);

done:
  if (r != HSK_SUCCESS)
    hsk_brontide_destroy(b);

  return r;
}

int
hsk_brontide_on_read(hsk_brontide_t *b, const uint8_t *data, size_t data_len) {
  if (b->state == BRONTIDE_ACT_NONE)
    return HSK_SUCCESS;

  assert(b->msg);

  while (b->msg_pos + data_len >= b->msg_len) {
    assert(b->msg_pos < b->msg_len);

    size_t need = b->msg_len - b->msg_pos;

    memcpy(&b->msg[b->msg_pos], data, need);

    data += need;
    data_len -= need;

    size_t msg_len;
    int r = hsk_brontide_parse(b, b->msg, b->msg_len, &msg_len);

    if (r != HSK_SUCCESS) {
      hsk_brontide_destroy(b);
      return r;
    }

    if (b->state == BRONTIDE_ACT_NONE)
      return HSK_SUCCESS;

    assert(msg_len != 0);

    uint8_t *msg = realloc(b->msg, msg_len);

    if (!msg) {
      hsk_brontide_destroy(b);
      return HSK_ENOMEM;
    }

    b->msg = msg;
    b->msg_pos = 0;
    b->msg_len = msg_len;
  }

  memcpy(&b->msg[b->msg_pos], data, data_len);
  b->msg_pos += data_len;

  return HSK_SUCCESS;
}

int
hsk_brontide_parse(
  hsk_brontide_t *b,
  uint8_t *data,
  size_t data_len,
  size_t *msg_len
) {
  assert(b->connect_cb);
  assert(b->write_cb);
  assert(b->read_cb);

  int r;

  if (b->initiator) {
    switch (b->state) {
      case BRONTIDE_ACT_TWO: {
        assert(data_len == BRONTIDE_ACT_TWO_SIZE);

        if (!hsk_brontide_recv_act_two(b, data))
          return HSK_EACTTWO;

        uint8_t act3[BRONTIDE_ACT_THREE_SIZE];
        hsk_brontide_gen_act_three(b, act3);

        r = b->write_cb(b->write_arg, act3, BRONTIDE_ACT_THREE_SIZE, false);

        if (r != 0)
          return r;

        b->state = BRONTIDE_ACT_DONE;
        b->connect_cb(b->connect_arg);

        *msg_len = BRONTIDE_HEADER_SIZE;
        return HSK_SUCCESS;
      }

      default: {
        assert(b->state == BRONTIDE_ACT_DONE);
        break;
      }
    }
  } else {
    switch (b->state) {
      case BRONTIDE_ACT_ONE: {
        assert(data_len == BRONTIDE_ACT_ONE_SIZE);

        if (!hsk_brontide_recv_act_one(b, data))
          return HSK_EACTONE;

        uint8_t act2[BRONTIDE_ACT_TWO_SIZE];
        hsk_brontide_gen_act_two(b, act2);

        r = b->write_cb(b->write_arg, act2, BRONTIDE_ACT_TWO_SIZE, false);

        if (r != 0)
          return r;

        b->state = BRONTIDE_ACT_THREE;

        *msg_len = BRONTIDE_ACT_THREE_SIZE;
        return HSK_SUCCESS;
      }

      case BRONTIDE_ACT_THREE: {
        assert(data_len == BRONTIDE_ACT_THREE_SIZE);

        if (!hsk_brontide_recv_act_three(b, data))
          return HSK_EACTTHREE;

        b->state = BRONTIDE_ACT_DONE;
        b->connect_cb(b->connect_arg);

        *msg_len = BRONTIDE_HEADER_SIZE;
        return HSK_SUCCESS;
      }

      default: {
        assert(b->state == BRONTIDE_ACT_DONE);
        break;
      }
    }
  }

  if (!b->has_size) {
    assert(b->msg_len == BRONTIDE_HEADER_SIZE);
    assert(data_len == BRONTIDE_HEADER_SIZE);

    uint8_t *len = &data[0];
    uint8_t *tag = &data[4];

    hsk_cs_decrypt(&b->recv_cipher, NULL, len, len, 4);

    if (!hsk_cs_verify(&b->recv_cipher, tag))
      return HSK_EBADTAG;

    int32_t size = get_i32(len);

    if (size < 0 || size > BRONTIDE_MAX_MESSAGE)
      return HSK_EBADSIZE;

    b->has_size = true;

    *msg_len = size + 16;

    return HSK_SUCCESS;
  }

  uint8_t *payload = &data[0];
  size_t payload_len = data_len - 16;
  uint8_t *tag = &data[payload_len];

  hsk_cs_decrypt(&b->recv_cipher, NULL, payload, payload, payload_len);

  if (!hsk_cs_verify(&b->recv_cipher, tag))
    return HSK_EBADTAG;

  b->has_size = false;
  b->read_cb(b->read_arg, payload, payload_len);

  *msg_len = BRONTIDE_HEADER_SIZE;
  return HSK_SUCCESS;
}
