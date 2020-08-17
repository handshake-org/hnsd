#ifndef _HSK_EC_H
#define _HSK_EC_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "hash.h"
#include "secp256k1.h"

typedef hsk_secp256k1_context hsk_ec_t;

hsk_ec_t *
hsk_ec_alloc(void);

hsk_ec_t *
hsk_ec_clone(const hsk_ec_t *ec);

void
hsk_ec_free(hsk_ec_t *ec);

bool
hsk_ec_randomize(hsk_ec_t *ec, const uint8_t *seed);

bool
hsk_ec_verify_privkey(const hsk_ec_t *ec, const uint8_t *key);

bool
hsk_ec_verify_pubkey(const hsk_ec_t *ec, const uint8_t *key);

bool
hsk_ec_create_privkey(const hsk_ec_t *ec, uint8_t *key);

bool
hsk_ec_create_pubkey(const hsk_ec_t *ec, const uint8_t *key, uint8_t *pubkey);

bool
hsk_ec_sign_msg(
  const hsk_ec_t *ec,
  const uint8_t *key,
  const uint8_t *msg,
  uint8_t *sig,
  int *rec
);

bool
hsk_ec_verify_msg(
  const hsk_ec_t *ec,
  const uint8_t *pubkey,
  const uint8_t *msg,
  const uint8_t *sig
);

bool
hsk_ec_recover(
  const hsk_ec_t *ec,
  const uint8_t *msg,
  const uint8_t *sig,
  int rec,
  uint8_t *pubkey
);

bool
hsk_ec_verify_hash(
  const hsk_ec_t *ec,
  const uint8_t *msg,
  const uint8_t *sig,
  int rec,
  const uint8_t *keyhash
);

bool
hsk_ec_ecdh(
  const hsk_ec_t *ec,
  const uint8_t *pubkey,
  const uint8_t *key,
  uint8_t *result
);

bool
hsk_ec_pubkey_to_hash(
  const hsk_ec_t *ec,
  const uint8_t *pubkey,
  uint8_t *result
);

bool
hsk_ec_pubkey_from_hash(
  const hsk_ec_t *ec,
  const uint8_t *hash,
  uint8_t *result
);
#endif
