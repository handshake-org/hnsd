#ifndef HSK_SECP256K1_ECDH_H
#define HSK_SECP256K1_ECDH_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Compute an EC Diffie-Hellman secret in constant time
 *  Returns: 1: exponentiation was successful
 *           0: scalar was invalid (zero or overflow)
 *  Args:    ctx:        pointer to a context object (cannot be NULL)
 *  Out:     result:     a 32-byte array which will be populated by an ECDH
 *                       secret computed from the point and scalar
 *  In:      pubkey:     a pointer to a hsk_secp256k1_pubkey containing an
 *                       initialized public key
 *           privkey:    a 32-byte scalar with which to multiply the point
 */
HSK_SECP256K1_API HSK_SECP256K1_WARN_UNUSED_RESULT int hsk_secp256k1_ecdh(
  const hsk_secp256k1_context* ctx,
  unsigned char *result,
  const hsk_secp256k1_pubkey *pubkey,
  const unsigned char *privkey
) HSK_SECP256K1_ARG_NONNULL(1) HSK_SECP256K1_ARG_NONNULL(2) HSK_SECP256K1_ARG_NONNULL(3) HSK_SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* HSK_SECP256K1_ECDH_H */
