#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "hsk-ec.h"
#include "hsk-hash.h"
#include "hsk-hsig.h"

bool
hsk_hsig_get_nonce(
  uint8_t *wire,
  size_t wire_len,
  uint8_t *nonce
) {
  if (wire_len < 43 + 12)
    return false;

  uint16_t arcount = (((uint16_t)wire[10]) << 8) | wire[11];

  if (arcount < 1)
    return false;

  uint8_t *rr = (wire + wire_len) - 43;

  // Name should be `.`.
  if (rr[0] != 0)
    return false;

  uint16_t type = (((uint16_t)rr[1]) << 8) | rr[2];
  uint16_t class = (((uint16_t)rr[3]) << 8) | rr[4];
  uint32_t ttl = 0
    | (((uint32_t)rr[5]) << 24)
    | (((uint32_t)rr[6]) << 16)
    | (((uint32_t)rr[7]) << 8)
    | ((uint32_t)rr[8]);
  uint16_t size = (((uint16_t)rr[9]) << 8) | rr[10];

  // Type
  if (type != HDK_DNS_HNONCE)
    return false;

  // Class
  if (class != 1)
    return false;

  // TTL
  if (ttl != 0)
    return false;

  // RD size
  if (size != 32)
    return false;

  // Copy nonce.
  memcpy(nonce, rr + 11, 32);

  return true;
}

bool
hsk_hsig_add_nonce(
  uint8_t *wire,
  size_t wire_len,
  uint8_t *nonce,
  uint8_t **out,
  size_t *out_len
) {
  if (wire_len < 12)
    return false;

  uint16_t arcount = (((uint16_t)wire[10]) << 8) | wire[11];

  size_t o_len = wire_len + 43;
  uint8_t *o = malloc(o_len);

  if (!o)
    return false;

  memcpy(o, wire, wire_len);

  uint8_t *rr = o + wire_len;

  // name = .
  rr[0] = 0;

  // rr_type = HNONCE
  rr[1] = HDK_DNS_HNONCE >> 8;
  rr[2] = HDK_DNS_HNONCE & 0xff;

  // rr_class = INET
  rr[3] = 1 >> 8;
  rr[4] = 1 & 0xff;

  // rr_ttl = 0
  rr[5] = 0;
  rr[6] = 0;
  rr[7] = 0;
  rr[8] = 0;

  // rd_len = 32
  rr[9] = 0;
  rr[10] = 32;

  // rd = nonce
  memcpy(rr + 11, nonce, 32);

  // arcount + 1
  arcount += 1;
  o[10] = arcount >> 8;
  o[11] = arcount & 0xff;

  *out = o;
  *out_len = o_len;

  return true;
}

bool
hsk_hsig_get_sig(
  uint8_t *wire,
  size_t wire_len,
  uint8_t *sig,
  int32_t *rec
) {
  if (wire_len < 76 + 12)
    return false;

  uint16_t arcount = (((uint16_t)wire[10]) << 8) | wire[11];

  if (arcount < 1)
    return false;

  uint8_t *rr = (wire + wire_len) - 76;

  // Name should be `.`.
  if (rr[0] != 0)
    return false;

  uint16_t type = (((uint16_t)rr[1]) << 8) | rr[2];
  uint16_t class = (((uint16_t)rr[3]) << 8) | rr[4];
  uint32_t ttl = 0
    | (((uint32_t)rr[5]) << 24)
    | (((uint32_t)rr[6]) << 16)
    | (((uint32_t)rr[7]) << 8)
    | ((uint32_t)rr[8]);
  uint16_t size = (((uint16_t)rr[9]) << 8) | rr[10];

  // Type
  if (type != HSK_DNS_HSIG)
    return false;

  // Class
  if (class != 1)
    return false;

  // TTL
  if (ttl != 0)
    return false;

  // RD size
  if (size != 65)
    return false;

  // Copy to temporary buffer while we append the nonce.
  memcpy(sig, rr + 11, 64);
  *rec = (rr + 11)[64];

  return true;
}

bool
hsk_hsig_sighash(
  uint8_t *wire,
  size_t wire_len,
  uint8_t *nonce,
  uint8_t *hash
) {
  uint8_t sig[64];
  int32_t rec;

  if (!hsk_hsig_get_sig(wire, wire_len, sig, &rec))
    return false;

  uint8_t *rr = (wire + wire_len) - 76;

  // Replace signature record with nonce record.
  rr[1] = HDK_DNS_HNONCE >> 8;
  rr[2] = HDK_DNS_HNONCE & 0xff;
  rr[10] = 32;
  memcpy(rr + 11, nonce, 32);

  // Hash the message, minus the 33 bytes we removed.
  hsk_hash_blake2b(wire, wire_len - 33, hash);

  // Put the sig back.
  rr[1] = HSK_DNS_HSIG >> 8;
  rr[2] = HSK_DNS_HSIG & 0xff;
  rr[10] = 65;
  memcpy(rr + 11, sig, 64);
  (rr + 11)[64] = (uint8_t)rec;

  return true;
}

bool
hsk_hsig_sign(
  hsk_ec_t *ctx,
  uint8_t *key,
  uint8_t *wire,
  size_t wire_len,
  uint8_t *nonce,
  uint8_t **out,
  size_t *out_len
) {
  if (wire_len < 12)
    return false;

  uint16_t arcount = (((uint16_t)wire[10]) << 8) | wire[11];

  size_t o_len = wire_len + 76;
  uint8_t *o = malloc(o_len);

  if (!o)
    return false;

  memcpy(o, wire, wire_len);

  uint8_t *rr = o + wire_len;

  // name = .
  rr[0] = 0;

  // rr_type = HSIG
  rr[1] = HSK_DNS_HSIG >> 8;
  rr[2] = HSK_DNS_HSIG & 0xff;

  // rr_class = INET
  rr[3] = 1 >> 8;
  rr[4] = 1 & 0xff;

  // rr_ttl = 0
  rr[5] = 0;
  rr[6] = 0;
  rr[7] = 0;
  rr[8] = 0;

  // rd_len = 65
  rr[9] = 0;
  rr[10] = 65;

  // rd = sig
  memset(rr + 11, 0, 65);

  uint8_t hash[32];

  if (!hsk_hsig_sighash(o, o_len, nonce, hash)) {
    free(o);
    return false;
  }

  uint8_t *sig = rr + 11;
  int32_t rec;

  if (!hsk_ec_sign_msg(ctx, key, hash, sig, &rec)) {
    free(o);
    return false;
  }

  sig[64] = (uint8_t)rec;

  // arcount + 1
  arcount += 1;
  o[10] = arcount >> 8;
  o[11] = arcount & 0xff;

  *out = o;
  *out_len = o_len;

  return true;
}

bool
hsk_hsig_verify(
  hsk_ec_t *ctx,
  uint8_t *keyhash,
  uint8_t *wire,
  size_t wire_len,
  uint8_t *nonce
) {
  uint8_t sig[64];
  int32_t rec;

  if (!hsk_hsig_get_sig(wire, wire_len, sig, &rec))
    return false;

  uint8_t hash[32];
  assert(hsk_hsig_sighash(wire, wire_len, nonce, hash));

  return hsk_ec_verify_hash(ctx, hash, sig, rec, keyhash);
}

bool
hsk_hsig_sign_response(
  hsk_ec_t *ctx,
  uint8_t *key,
  uint8_t *wire,
  size_t wire_len,
  uint8_t *req,
  size_t req_len,
  uint8_t **out,
  size_t *out_len
) {
  uint8_t nonce[32];

  if (!hsk_hsig_get_nonce(req, req_len, nonce))
    return false;

  return hsk_hsig_sign(
    ctx,
    key,
    wire,
    wire_len,
    nonce,
    out,
    out_len
  );
}
