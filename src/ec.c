#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "secp256k1.h"
#include "secp256k1_recovery.h"
#include "secp256k1_ecdh.h"

#include "hsk-ec.h"
#include "hsk-hash.h"
#include "hsk-random.h"

hsk_ec_t *
hsk_ec_alloc(void) {
  return secp256k1_context_create(
    SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

hsk_ec_t *
hsk_ec_clone(hsk_ec_t *ec) {
  assert(ec);
  return secp256k1_context_clone(ec);
}

void
hsk_ec_free(hsk_ec_t *ec) {
  assert(ec);
  secp256k1_context_destroy(ec);
}

bool
hsk_ec_randomize(hsk_ec_t *ec, uint8_t *seed) {
  assert(ec && seed);
  return secp256k1_context_randomize(ec, seed) != 0;
}

bool
hsk_ec_verify_privkey(hsk_ec_t *ec, uint8_t *key) {
  assert(ec && key);
  return secp256k1_ec_seckey_verify(ec, key) != 0;
}

bool
hsk_ec_verify_pubkey(hsk_ec_t *ec, uint8_t *key) {
  assert(ec && key);
  secp256k1_pubkey pub;
  return secp256k1_ec_pubkey_parse(ec, &pub, key, 33) != 0;
}

bool
hsk_ec_create_privkey(hsk_ec_t *ec, uint8_t *key) {
  assert(ec && key);

  memset(key, 0, 32);

  int32_t i = 0;

  while (!hsk_ec_verify_privkey(ec, key)) {
    if (i > 100000)
      return false;

    if (!hsk_randombytes(key, 32))
      return false;

    i += 1;
  }

  return true;
}

bool
hsk_ec_create_pubkey(hsk_ec_t *ec, uint8_t *key, uint8_t *pubkey) {
  assert(ec && key && pubkey);

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_create(ec, &pub, key))
    return false;

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  size_t len = 33;

  if (!secp256k1_ec_pubkey_serialize(ec, pubkey, &len, &pub, flags))
    return false;

  assert(len == 33);

  return true;
}

bool
hsk_ec_sign_msg(
  hsk_ec_t *ec,
  uint8_t *key,
  uint8_t *msg,
  uint8_t *sig,
  int32_t *rec
) {
  assert(ec && key && sig);

  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;

  secp256k1_ecdsa_recoverable_signature s;

  int32_t result = secp256k1_ecdsa_sign_recoverable(
    ec,
    &s,
    msg,
    key,
    noncefn,
    NULL
  );

  if (result == 0)
    return false;

  secp256k1_ecdsa_recoverable_signature_serialize_compact(ec, sig, rec, &s);

  return true;
}

bool
hsk_ec_verify_msg(
  hsk_ec_t *ec,
  uint8_t *pubkey,
  uint8_t *msg,
  uint8_t *sig
) {
  assert(ec && pubkey && msg && sig);

  secp256k1_ecdsa_signature s;

  if (!secp256k1_ecdsa_signature_parse_compact(ec, &s, sig))
    return false;

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_parse(ec, &pub, pubkey, 33))
    return false;

  if (!secp256k1_ecdsa_verify(ec, &s, msg, &pub))
    return false;

  return true;
}

bool
hsk_ec_recover(
  hsk_ec_t *ec,
  uint8_t *msg,
  uint8_t *sig,
  int32_t rec,
  uint8_t *pubkey
) {
  assert(ec && msg && sig && pubkey);

  secp256k1_ecdsa_recoverable_signature s;

  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ec, &s, sig, rec))
    return false;

  secp256k1_pubkey pub;

  if (!secp256k1_ecdsa_recover(ec, &pub, &s, msg))
    return false;

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  size_t len = 33;

  if (!secp256k1_ec_pubkey_serialize(ec, pubkey, &len, &pub, flags))
    return false;

  assert(len == 33);

  return true;
}

bool
hsk_ec_verify_hash(
  hsk_ec_t *ec,
  uint8_t *msg,
  uint8_t *sig,
  int32_t rec,
  uint8_t *keyhash
) {
  assert(ec && msg && sig && keyhash);

  uint8_t key[33];

  if (!hsk_ec_recover(ec, msg, sig, rec, key))
    return false;

  hsk_hash_blake2b(key, 33, key);

  return memcmp(key, keyhash, 32) == 0;
}

bool
hsk_ec_ecdh(hsk_ec_t *ec, uint8_t *pubkey, uint8_t *key, uint8_t *result) {
  assert(ec && pubkey && key && result);

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_parse(ec, &pub, pubkey, 33))
    return false;

  // NOTE: This always does SHA256.
  if (!secp256k1_ecdh(ec, result, &pub, key))
    return false;

  return true;
}
