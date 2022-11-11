#include <assert.h>
#include <stdio.h>

#include "base32.h"

static void
test_base32_encode_decode() {
  const char *str = "5l6tm80";
  const uint8_t expected[4] = {45, 77, 219, 32};

  uint8_t ip[4];
  hsk_base32_decode_hex(str, ip, false);
  for (int i = 0; i < 4; i++) {
    assert(ip[i] == expected[i]);
  }

  char encoded[8];
  hsk_base32_encode_hex(ip, 4, encoded, false);
  assert(strcmp(encoded, str) == 0);
}

void
test_base32() {
  printf(" test_base32_encode_decode\n");
  test_base32_encode_decode();
}
