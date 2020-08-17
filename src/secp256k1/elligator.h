#ifndef HSK_SECP256K1_ELLIGATOR_H
#define HSK_SECP256K1_ELLIGATOR_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Hash bytes to a point using the Shallue-van de Woestijne map.
 *
 *  Returns: 1: the byte array was sucessfully mapped.
 *           0: invalid arguments.
 *  Args:    ctx:      pointer to a context object (cannot be NULL).
 *  Out:     pubkey:   pointer to a pubkey object.
 *  In:      bytes32:  pointer to a raw 32-byte field element.
 */
HSK_SECP256K1_API HSK_SECP256K1_WARN_UNUSED_RESULT int
hsk_secp256k1_ec_pubkey_from_uniform(const hsk_secp256k1_context *ctx,
                                     hsk_secp256k1_pubkey *pubkey,
                                     const unsigned char *bytes32) HSK_SECP256K1_ARG_NONNULL(1)
                                                                   HSK_SECP256K1_ARG_NONNULL(2)
                                                                   HSK_SECP256K1_ARG_NONNULL(3);

/** Convert a point to bytes by inverting the Shallue-van de Woestijne map.
 *  The preimage must be explicitly selected with the `hint` argument.
 *
 *  Returns: 1: the point was sucessfully inverted.
 *           0: no inverse for given preimage index.
 *  Args:    ctx:     pointer to a context object (cannot be NULL).
 *  Out:     bytes32: pointer to a 32-byte array to be filled by the function.
 *  In:      pubkey:  pointer to a hsk_secp256k1_pubkey containing an
 *                    initialized public key.
 *           hint:    preimage index (ranges from 0 to 3 inclusive).
 */
HSK_SECP256K1_API HSK_SECP256K1_WARN_UNUSED_RESULT int
hsk_secp256k1_ec_pubkey_to_uniform(const hsk_secp256k1_context *ctx,
                                   unsigned char *bytes32,
                                   const hsk_secp256k1_pubkey *pubkey,
                                   unsigned int hint) HSK_SECP256K1_ARG_NONNULL(1)
                                                      HSK_SECP256K1_ARG_NONNULL(2)
                                                      HSK_SECP256K1_ARG_NONNULL(3);

/** Hash bytes to a point using the Shallue-van de Woestijne map.
 *
 *  Returns: 1: the point was sucessfully created.
 *           0: point is at infinity.
 *  Args:    ctx:      pointer to a context object (cannot be NULL).
 *  Out:     pubkey:   pointer to a pubkey object.
 *  In:      bytes64:  pointer to two raw concatenated 32-byte field elements.
 */
HSK_SECP256K1_API HSK_SECP256K1_WARN_UNUSED_RESULT int
hsk_secp256k1_ec_pubkey_from_hash(const hsk_secp256k1_context *ctx,
                                  hsk_secp256k1_pubkey *pubkey,
                                  const unsigned char *bytes64) HSK_SECP256K1_ARG_NONNULL(1)
                                                                HSK_SECP256K1_ARG_NONNULL(2)
                                                                HSK_SECP256K1_ARG_NONNULL(3);

/** Convert a point to bytes by inverting the Shallue-van de Woestijne map.
 *
 *  Returns: 1: the point was sucessfully inverted.
 *           0: pubkey is invalid.
 *  Args:    ctx:     pointer to a context object (cannot be NULL).
 *  Out:     bytes64: pointer to a 64-byte array to be filled by the function.
 *  In:      pubkey:  pointer to a hsk_secp256k1_pubkey containing an
 *                    initialized public key.
 *           entropy: pointer to a 32-byte random seed.
 */
HSK_SECP256K1_API HSK_SECP256K1_WARN_UNUSED_RESULT int
hsk_secp256k1_ec_pubkey_to_hash(const hsk_secp256k1_context *ctx,
                                unsigned char *bytes64,
                                const hsk_secp256k1_pubkey *pubkey,
                                const unsigned char *entropy) HSK_SECP256K1_ARG_NONNULL(1)
                                                              HSK_SECP256K1_ARG_NONNULL(2)
                                                              HSK_SECP256K1_ARG_NONNULL(3)
                                                              HSK_SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* HSK_SECP256K1_ELLIGATOR_H */
