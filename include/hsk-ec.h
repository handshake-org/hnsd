#ifndef _HSK_EC_H
#define _HSK_EC_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "secp256k1.h"

#include "hsk-hash.h"

typedef secp256k1_context hsk_ec_t;

hsk_ec_t *
hsk_ec_alloc(void);

hsk_ec_t *
hsk_ec_clone(hsk_ec_t *ec);

void
hsk_ec_free(hsk_ec_t *ec);

bool
hsk_ec_randomize(hsk_ec_t *ctx, uint8_t *seed);

bool
hsk_ec_verify_privkey(hsk_ec_t *ctx, uint8_t *key);

bool
hsk_ec_verify_pubkey(hsk_ec_t *ctx, uint8_t *key);

bool
hsk_ec_create_pubkey(hsk_ec_t *ctx, uint8_t *key, uint8_t *pubkey);

bool
hsk_ec_sign_msg(
  hsk_ec_t *ctx,
  uint8_t *key,
  uint8_t *msg,
  uint8_t *sig,
  int32_t *rec
);

bool
hsk_ec_verify_msg(
  hsk_ec_t *ctx,
  uint8_t *pubkey,
  uint8_t *msg,
  uint8_t *sig
);

bool
hsk_ec_recover(
  hsk_ec_t *ctx,
  uint8_t *msg,
  uint8_t *sig,
  int32_t rec,
  uint8_t *pubkey
);

bool
hsk_ec_verify_hash(
  hsk_ec_t *ctx,
  uint8_t *msg,
  uint8_t *sig,
  int32_t rec,
  uint8_t *keyhash
);
#endif
