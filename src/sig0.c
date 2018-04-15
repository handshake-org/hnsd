#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "bio.h"
#include "blake2b.h"
#include "dns.h"
#include "ec.h"
#include "sig0.h"
#include "utils.h"

bool
hsk_sig0_has_sig(const uint8_t *wire, size_t wire_len) {
  if (wire_len < HSK_SIG0_RR_SIZE + 12)
    return false;

  uint16_t arcount = get_u16be(&wire[10]);

  if (arcount < 1)
    return false;

  const uint8_t *rr = &wire[wire_len - HSK_SIG0_RR_SIZE];

  // Name should be `.`.
  if (rr[0] != 0)
    return false;

  uint16_t type = get_u16be(&rr[1]);
  uint16_t class = get_u16be(&rr[3]);
  uint32_t ttl = get_u32be(&rr[5]);
  uint16_t size = get_u16be(&rr[9]);
  const uint8_t *rd = &rr[11];

  // Type
  if (type != HSK_SIG0_TYPE)
    return false;

  // Class (ANY)
  if (class != HSK_SIG0_CLASS)
    return false;

  // TTL
  if (ttl != 0)
    return false;

  // RD size
  if (size != HSK_SIG0_RD_SIZE)
    return false;

  uint16_t type_covered = get_u16be(&rd[0]);

  // Must be SIG(0).
  if (type_covered != HSK_SIG0_ZERO)
    return false;

  return true;
}

bool
hsk_sig0_get_sig(
  const uint8_t *wire,
  size_t wire_len,
  uint8_t *sig,
  uint16_t *tag
) {
  if (!hsk_sig0_has_sig(wire, wire_len))
    return false;

  const uint8_t *rr = &wire[wire_len - HSK_SIG0_RR_SIZE];
  const uint8_t *rd = &rr[11];

  uint16_t type_covered = get_u16be(&rd[0]);
  uint8_t algorithm = get_u8(&rd[2]);
  uint8_t labels = get_u8(&rd[3]);
  uint32_t orig_ttl = get_u32be(&rd[4]);
  uint32_t expiration = get_u32be(&rd[8]);
  uint32_t inception = get_u32be(&rd[12]);
  uint16_t key_tag = get_u16be(&rd[16]);
  uint16_t signer_name = get_u8(&rd[18]);

  // Must be SIG(0).
  if (type_covered != HSK_SIG0_ZERO)
    return false;

  // Must be PRIVATEDNS.
  if (algorithm != HSK_SIG0_ALG)
    return false;

  // Unused.
  if (labels != 0 || orig_ttl != 0)
    return false;

  // Must be `.`.
  if (signer_name != 0)
    return false;

  // Must match time.
  uint32_t now = (uint32_t)hsk_now();

  if (now < inception)
    return false;

  if (now > expiration)
    return false;

  // Copy sig.
  if (sig)
    memcpy(sig, &rd[19], 64);

  // Copy key tag.
  if (tag)
    *tag = key_tag;

  return true;
}

bool
hsk_sig0_sighash(const uint8_t *wire, size_t wire_len, uint8_t *hash) {
  if (!hsk_sig0_has_sig(wire, wire_len))
    return false;

  uint16_t arcount = get_u16be(&wire[10]);
  const uint8_t *rr = &wire[wire_len - HSK_SIG0_RR_SIZE];
  const uint8_t *rd = &rr[11];

  // Decrement arcount.
  uint8_t count[2];
  set_u16be(&count[0], arcount - 1);

  hsk_blake2b_ctx ctx;
  assert(hsk_blake2b_init(&ctx, 32) == 0);

  // SIG rdata (without signature bytes).
  hsk_blake2b_update(&ctx, &rd[0], 19);

  // Message header with decremented arcount.
  hsk_blake2b_update(&ctx, &wire[0], 10);
  hsk_blake2b_update(&ctx, &count[0], 2);

  // Message body, stopping just before SIG record.
  hsk_blake2b_update(&ctx, &wire[12], wire_len - 12 - HSK_SIG0_RR_SIZE);

  assert(hsk_blake2b_final(&ctx, hash, 32) == 0);

  return true;
}

bool
hsk_sig0_sign(
  const hsk_ec_t *ec,
  const uint8_t *key,
  const uint8_t *wire,
  size_t wire_len,
  uint8_t **out,
  size_t *out_len
) {
  if (wire_len < 12)
    return false;

  uint16_t arcount = get_u16be(&wire[10]);
  arcount += 1;

  size_t o_len = wire_len + HSK_SIG0_RR_SIZE;

  // Overwrite sigs. Do not append.
  if (hsk_sig0_has_sig(wire, wire_len)) {
    o_len -= HSK_SIG0_RR_SIZE;
    wire_len -= HSK_SIG0_RR_SIZE;
    arcount -= 1;
  }

  uint8_t *o = malloc(o_len);

  if (!o)
    return false;

  memcpy(o, wire, wire_len);

  // arcount + 1
  set_u16be(&o[10], arcount);

  uint8_t *rr = &o[wire_len];
  uint8_t *rd = &rr[11];

  // name = .
  set_u8(&rr[0], 0);

  // rr_type = SIG
  set_u16be(&rr[1], HSK_SIG0_TYPE);

  // rr_class = ANY
  set_u16be(&rr[3], HSK_SIG0_CLASS);

  // rr_ttl = 0
  set_u32be(&rr[5], 0);

  // rd_len = 83
  set_u16be(&rr[9], HSK_SIG0_RD_SIZE);

  // type_covered = 0
  set_u16be(&rd[0], HSK_SIG0_ZERO);

  // algorithm = PRIVATEDNS
  set_u8(&rd[2], HSK_SIG0_ALG);

  // labels = 0
  set_u8(&rd[3], 0);

  // orig_ttl = 0
  set_u32be(&rd[4], 0);

  uint32_t now = (uint32_t)hsk_now();

  // expiration
  set_u32be(&rd[8], now + 6 * 60 * 60);

  // inception
  set_u32be(&rd[12], now - 6 * 60 * 60);

  // key_tag
  set_u16be(&rd[16], 0);

  // signer_name = .
  set_u8(&rd[18], 0);

  // signature
  memset(&rd[19], 0, 64);

  uint8_t hash[32];

  if (!hsk_sig0_sighash(o, o_len, hash)) {
    free(o);
    return false;
  }

  uint8_t *sig = &rd[19];
  int32_t rec;

  if (!hsk_ec_sign_msg(ec, key, hash, sig, &rec)) {
    free(o);
    return false;
  }

  *out = o;
  *out_len = o_len;

  return true;
}

bool
hsk_sig0_verify(
  const hsk_ec_t *ec,
  const uint8_t *pubkey,
  const uint8_t *wire,
  size_t wire_len
) {
  uint8_t sig[64];
  uint16_t tag;

  if (!hsk_sig0_get_sig(wire, wire_len, sig, &tag))
    return false;

  uint8_t hash[32];
  assert(hsk_sig0_sighash(wire, wire_len, hash));

  return hsk_ec_verify_msg(ec, pubkey, hash, sig);
}
