#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "secp256k1.h"
#include "secp256k1_recovery.h"

#include "hsk-hash.h"
#include "ec.h"

hsk_ec_t *
hsk_ec_alloc(void) {
  return secp256k1_context_create(
    SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

bool
hsk_ec_randomize(hsk_ec_t *ctx, uint8_t *seed) {
  return secp256k1_context_randomize(ctx, seed) != 0;
}

bool
hsk_ec_verify_privkey(hsk_ec_t *ctx, uint8_t *key) {
  return secp256k1_ec_seckey_verify(ctx, key) != 0;
}

bool
hsk_ec_verify_pubkey(hsk_ec_t *ctx, uint8_t *key) {
  secp256k1_pubkey pub;
  return secp256k1_ec_pubkey_parse(ctx, &pub, key, 33) != 0;
}

bool
hsk_ec_create_pubkey(hsk_ec_t *ctx, uint8_t *key, uint8_t *pubkey) {
  assert(ctx && key);

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_create(ctx, &pub, key))
    return false;

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  size_t len = 33;

  if (!secp256k1_ec_pubkey_serialize(ctx, pubkey, &len, &pub, flags))
    return false;

  assert(len == 33);

  return true;
}

bool
hsk_ec_sign_msg(
  hsk_ec_t *ctx,
  uint8_t *key,
  uint8_t *msg,
  uint8_t *sig,
  int32_t *rec
) {
  assert(ctx && key && sig);

  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;

  secp256k1_ecdsa_recoverable_signature s;

  int32_t result = secp256k1_ecdsa_sign_recoverable(
    ctx,
    &s,
    msg,
    key,
    noncefn,
    NULL
  );

  if (result == 0)
    return false;

  secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig, rec, &s);

  return true;
}

bool
hsk_ec_verify_msg(
  hsk_ec_t *ctx,
  uint8_t *pubkey,
  uint8_t *msg,
  uint8_t *sig
) {
  secp256k1_ecdsa_signature s;

  if (!secp256k1_ecdsa_signature_parse_compact(ctx, &s, sig))
    return false;

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_parse(ctx, &pub, pubkey, 33))
    return false;

  if (!secp256k1_ecdsa_verify(ctx, &s, msg, &pub))
    return false;

  return true;
}

bool
hsk_ec_recover(
  hsk_ec_t *ctx,
  uint8_t *msg,
  uint8_t *sig,
  int32_t rec,
  uint8_t *pubkey
) {
  secp256k1_ecdsa_recoverable_signature s;

  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &s, sig, rec))
    return false;

  secp256k1_pubkey pub;

  if (!secp256k1_ecdsa_recover(ctx, &pub, &s, msg))
    return false;

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  size_t len = 33;

  if (!secp256k1_ec_pubkey_serialize(ctx, pubkey, &len, &pub, flags))
    return false;

  assert(len == 33);

  return true;
}

bool
hsk_ec_verify_hash(
  hsk_ec_t *ctx,
  uint8_t *msg,
  uint8_t *sig,
  int32_t rec,
  uint8_t *keyhash
) {
  uint8_t key[33];

  if (!hsk_ec_recover(ctx, msg, sig, rec, key))
    return false;

  hsk_hash_blake2b(key, 33, key);

  return memcmp(key, keyhash, 32) == 0;
}
