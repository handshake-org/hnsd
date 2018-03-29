/**
 * Parts of this software are based on poly1305-donna:
 * https://github.com/floodyberry/poly1305-donna
 *
 * MIT License
 * http://www.opensource.org/licenses/mit-license.php
 */

#ifndef _HSK_POLY1305_H
#define _HSK_POLY1305_H

#include <stddef.h>

typedef struct hsk_poly1305_ctx_s {
  size_t aligner;
  unsigned char opaque[136];
} hsk_poly1305_ctx;

void
hsk_poly1305_init(hsk_poly1305_ctx *ctx, const unsigned char key[32]);

void
hsk_poly1305_update(
  hsk_poly1305_ctx *ctx,
  const unsigned char *m,
  size_t bytes
);

void
hsk_poly1305_finish(hsk_poly1305_ctx *ctx, unsigned char mac[16]);

void
hsk_poly1305_auth(
  unsigned char mac[16],
  const unsigned char *m,
  size_t bytes,
  const unsigned char key[32]
);

int
hsk_poly1305_verify(const unsigned char mac1[16], const unsigned char mac2[16]);

int
hsk_poly1305_power_on_self_test(void);

#endif
