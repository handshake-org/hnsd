#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "ec.h"
#include "hash.h"
#include "random.h"
#include "secp256k1.h"

hsk_ec_t *
hsk_ec_alloc(void) {
  return hsk_secp256k1_context_create(
    HSK_SECP256K1_CONTEXT_SIGN | HSK_SECP256K1_CONTEXT_VERIFY);
}

hsk_ec_t *
hsk_ec_clone(const hsk_ec_t *ec) {
  assert(ec);
  return hsk_secp256k1_context_clone(ec);
}

void
hsk_ec_free(hsk_ec_t *ec) {
  assert(ec);
  hsk_secp256k1_context_destroy(ec);
}

bool
hsk_ec_randomize(hsk_ec_t *ec, const uint8_t *seed) {
  assert(ec && seed);
  return hsk_secp256k1_context_randomize(ec, seed) != 0;
}

bool
hsk_ec_verify_privkey(const hsk_ec_t *ec, const uint8_t *key) {
  assert(ec && key);
  return hsk_secp256k1_ec_seckey_verify(ec, key) != 0;
}

bool
hsk_ec_verify_pubkey(const hsk_ec_t *ec, const uint8_t *key) {
  assert(ec && key);
  hsk_secp256k1_pubkey pub;
  return hsk_secp256k1_ec_pubkey_parse(ec, &pub, key, 33) != 0;
}

bool
hsk_ec_create_privkey(const hsk_ec_t *ec, uint8_t *key) {
  assert(ec && key);

  memset(key, 0, 32);

  int i = 0;

  while (!hsk_ec_verify_privkey(ec, key)) {
    if (i > 1000)
      return false;

    if (!hsk_randombytes(key, 32))
      return false;

    i += 1;
  }

  return true;
}

bool
hsk_ec_create_pubkey(const hsk_ec_t *ec, const uint8_t *key, uint8_t *pubkey) {
  assert(ec && key && pubkey);

  hsk_secp256k1_pubkey pub;

  if (!hsk_secp256k1_ec_pubkey_create(ec, &pub, key))
    return false;

  unsigned int flags = HSK_SECP256K1_EC_COMPRESSED;
  size_t len = 33;

  if (!hsk_secp256k1_ec_pubkey_serialize(ec, pubkey, &len, &pub, flags))
    return false;

  assert(len == 33);

  return true;
}

bool
hsk_ec_sign_msg(
  const hsk_ec_t *ec,
  const uint8_t *key,
  const uint8_t *msg,
  uint8_t *sig,
  int *rec
) {
  assert(ec && key && sig);

  hsk_secp256k1_nonce_function noncefn = hsk_secp256k1_nonce_function_rfc6979;

  hsk_secp256k1_ecdsa_recoverable_signature s;

  int result = hsk_secp256k1_ecdsa_sign_recoverable(
    ec,
    &s,
    msg,
    key,
    noncefn,
    NULL
  );

  if (result == 0)
    return false;

  hsk_secp256k1_ecdsa_recoverable_signature_serialize_compact(ec, sig, rec, &s);

  return true;
}

bool
hsk_ec_verify_msg(
  const hsk_ec_t *ec,
  const uint8_t *pubkey,
  const uint8_t *msg,
  const uint8_t *sig
) {
  assert(ec && pubkey && msg && sig);

  hsk_secp256k1_ecdsa_signature s;

  if (!hsk_secp256k1_ecdsa_signature_parse_compact(ec, &s, sig))
    return false;

  hsk_secp256k1_pubkey pub;

  if (!hsk_secp256k1_ec_pubkey_parse(ec, &pub, pubkey, 33))
    return false;

  if (!hsk_secp256k1_ecdsa_verify(ec, &s, msg, &pub))
    return false;

  return true;
}

bool
hsk_ec_recover(
  const hsk_ec_t *ec,
  const uint8_t *msg,
  const uint8_t *sig,
  int rec,
  uint8_t *pubkey
) {
  assert(ec && msg && sig && pubkey);

  hsk_secp256k1_ecdsa_recoverable_signature s;

  if (!hsk_secp256k1_ecdsa_recoverable_signature_parse_compact(ec, &s, sig, rec))
    return false;

  hsk_secp256k1_pubkey pub;

  if (!hsk_secp256k1_ecdsa_recover(ec, &pub, &s, msg))
    return false;

  unsigned int flags = HSK_SECP256K1_EC_COMPRESSED;
  size_t len = 33;

  if (!hsk_secp256k1_ec_pubkey_serialize(ec, pubkey, &len, &pub, flags))
    return false;

  assert(len == 33);

  return true;
}

bool
hsk_ec_verify_hash(
  const hsk_ec_t *ec,
  const uint8_t *msg,
  const uint8_t *sig,
  int rec,
  const uint8_t *keyhash
) {
  assert(ec && msg && sig && keyhash);

  uint8_t key[33];

  if (!hsk_ec_recover(ec, msg, sig, rec, key))
    return false;

  hsk_hash_blake2b(key, 33, key);

  return memcmp(key, keyhash, 32) == 0;
}

bool
hsk_ec_ecdh(
  const hsk_ec_t *ec,
  const uint8_t *pubkey,
  const uint8_t *key,
  uint8_t *result
) {
  assert(ec && pubkey && key && result);

  hsk_secp256k1_pubkey pub;

  if (!hsk_secp256k1_ec_pubkey_parse(ec, &pub, pubkey, 33))
    return false;

  // NOTE: This always does SHA256.
  if (!hsk_secp256k1_ecdh(ec, result, &pub, key))
    return false;

  return true;
}

bool
hsk_ec_pubkey_to_hash(
  const hsk_ec_t *ec,
  const uint8_t *pubkey,
  uint8_t *result
) {
  assert(ec && pubkey && result);

  hsk_secp256k1_pubkey pub;

  if (!hsk_secp256k1_ec_pubkey_parse(ec, &pub, pubkey, 33))
    return false;

  uint8_t entropy[32];
  if(!hsk_randombytes(entropy, 32))
    return false;

  if (!hsk_secp256k1_ec_pubkey_to_hash(ec, result, &pub, entropy))
    return false;

  return true;
}

bool
hsk_ec_pubkey_from_hash(
  const hsk_ec_t *ec,
  const uint8_t *hash,
  uint8_t *result
) {
  assert(ec && hash && result);

  hsk_secp256k1_pubkey pub;

  if (!hsk_secp256k1_ec_pubkey_from_hash(ec, &pub, hash))
    return false;

  unsigned int flags = HSK_SECP256K1_EC_COMPRESSED;
  size_t len = 33;

  if (!hsk_secp256k1_ec_pubkey_serialize(ec, result, &len, &pub, flags))
    return false;

  assert(len == 33);

  return true;
}
