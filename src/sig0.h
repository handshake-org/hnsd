#ifndef _HSK_SIG0_H
#define _HSK_SIG0_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "ec.h"

#define HSK_SIG0_RR_SIZE 94
#define HSK_SIG0_RD_SIZE 83

#define HSK_SIG0_TYPE 24
#define HSK_SIG0_CLASS 255
#define HSK_SIG0_ZERO 0
#define HSK_SIG0_ALG 253

bool
hsk_sig0_has_sig(const uint8_t *wire, size_t wire_len);

bool
hsk_sig0_get_sig(
  const uint8_t *wire,
  size_t wire_len,
  uint8_t *sig,
  uint16_t *tag
);

bool
hsk_sig0_sighash(const uint8_t *wire, size_t wire_len, uint8_t *hash);

bool
hsk_sig0_sign(
  const hsk_ec_t *ec,
  const uint8_t *key,
  const uint8_t *wire,
  size_t wire_len,
  uint8_t **out,
  size_t *out_len
);

bool
hsk_sig0_verify(
  const hsk_ec_t *ec,
  const uint8_t *pubkey,
  const uint8_t *wire,
  size_t wire_len
);
#endif
