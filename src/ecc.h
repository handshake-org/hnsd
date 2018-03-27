/*
https://github.com/esxgx/easy-ecc
Copyright (c) 2013, Kenneth MacKay
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _HSK_ECC_H
#define _HSK_ECC_H

#include <stdint.h>

#define HSK_SECP128R1 16
#define HSK_SECP192R1 24
#define HSK_SECP256R1 32
#define HSK_SECP384R1 48

#ifndef HSK_ECC_CURVE
#  define HSK_ECC_CURVE HSK_SECP256R1
#endif

#if (HSK_ECC_CURVE != HSK_SECP128R1 \
  && HSK_ECC_CURVE != HSK_SECP192R1 \
  && HSK_ECC_CURVE != HSK_SECP256R1 \
  && HSK_ECC_CURVE != HSK_SECP384R1)
#  error "Must define HSK_ECC_CURVE to one of the available curves"
#endif

#define HSK_ECC_BYTES HSK_ECC_CURVE

#ifdef __cplusplus
extern "C"
{
#endif

int
hsk_ecc_make_key(
  uint8_t public_key[HSK_ECC_BYTES + 1],
  uint8_t private_key[HSK_ECC_BYTES]
);

int
hsk_ecc_make_pubkey(
  uint8_t private_key[HSK_ECC_BYTES],
  uint8_t public_key[HSK_ECC_BYTES * 2]
);

int
hsk_ecc_make_pubkey_compressed(
  uint8_t private_key[HSK_ECC_BYTES],
  uint8_t public_key[HSK_ECC_BYTES + 1]
);

int
hsk_ecdh_shared_secret(
  const uint8_t public_key[HSK_ECC_BYTES + 1],
  const uint8_t private_key[HSK_ECC_BYTES],
  uint8_t secret[HSK_ECC_BYTES]
);

int
hsk_ecdsa_sign(
  const uint8_t private_key[HSK_ECC_BYTES],
  const uint8_t hash[HSK_ECC_BYTES],
  uint8_t signature[HSK_ECC_BYTES * 2]
);

int
hsk_ecdsa_verify(
  const uint8_t public_key[HSK_ECC_BYTES + 1],
  const uint8_t hash[HSK_ECC_BYTES],
  const uint8_t signature[HSK_ECC_BYTES * 2]
);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* _HSK_ECC_H */
