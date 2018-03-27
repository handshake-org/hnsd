#ifndef _HSK_HSIG_H
#define _HSK_HSIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "ec.h"

#define HDK_DNS_HNONCE 598
#define HSK_DNS_HSIG 599

bool
hsk_hsig_get_nonce(uint8_t *wire, size_t wire_len, uint8_t *nonce);

bool
hsk_hsig_has_nonce(uint8_t *wire, size_t wire_len);

bool
hsk_hsig_set_nonce(
  uint8_t *wire,
  size_t wire_len,
  uint8_t *nonce,
  uint8_t **out,
  size_t *out_len
);

bool
hsk_hsig_get_sig(uint8_t *wire, size_t wire_len, uint8_t *sig, int32_t *rec);

bool
hsk_hsig_has_sig(uint8_t *wire, size_t wire_len);

bool
hsk_hsig_sighash(
  uint8_t *wire,
  size_t wire_len,
  uint8_t *nonce,
  uint8_t *hash
);

bool
hsk_hsig_sign(
  hsk_ec_t *ctx,
  uint8_t *key,
  uint8_t *wire,
  size_t wire_len,
  uint8_t *nonce,
  uint8_t **out,
  size_t *out_len
);

bool
hsk_hsig_verify(
  hsk_ec_t *ctx,
  uint8_t *keyhash,
  uint8_t *wire,
  size_t wire_len,
  uint8_t *nonce
);

bool
hsk_hsig_sign_msg(
  hsk_ec_t *ctx,
  uint8_t *key,
  uint8_t **wire,
  size_t *wire_len,
  uint8_t *nonce
);
#endif
