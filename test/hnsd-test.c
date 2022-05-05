#include <assert.h>
#include "base32.h"
#include "resource.h"
#include "resource.c"

void
print_array(uint8_t *arr, size_t size){
  for (int i = 0; i < size; i++) {
    printf("%x", arr[i]);
  }
  printf("\n");
}

void
test_base32() {
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
test_pointer_to_ip() {
  const char *str4 = "_5l6tm80._synth";
  const uint8_t expected4[4] = {45, 77, 219, 32};
  uint8_t ip4[4];
  uint16_t family4;

  bool ret4 = pointer_to_ip(str4, ip4, &family4);
  assert(ret4);
  for (int i = 0; i < 4; i++) {
    assert(ip4[i] == expected4[i]);
  }
  assert(family4 == HSK_DNS_A);

  const char *str6 = "_400hjs000l2gol000fvvsc9cpg._synth";
  const uint8_t expected6[16] = {
    0x20, 0x01, 0x19, 0xf0,
    0x00, 0x05, 0x45, 0x0c,
    0x54, 0x00, 0x03, 0xff,
    0xfe, 0x31, 0x2c, 0xcc
  };

  uint8_t ip6[16];
  uint16_t family6;

  bool ret6 = pointer_to_ip(str6, ip6, &family6);
  assert(ret6);
  for (int i = 0; i < 16; i++) {
    assert(ip6[i] == expected6[i]);
  }
  assert(family6 == HSK_DNS_AAAA);
}

void
test_name_dirty() {
  printf("test_name_dirty\n");

  assert(!hsk_dns_name_dirty("hello"));
  assert(!hsk_dns_name_dirty("HELLO"));
  assert(!hsk_dns_name_dirty("heLLo"));
  assert(!hsk_dns_name_dirty("HeLl0"));
  assert(!hsk_dns_name_dirty("hel-lo"));
  assert(!hsk_dns_name_dirty("1"));
  assert(!hsk_dns_name_dirty("000_000"));
  assert(!hsk_dns_name_dirty("this-domain-name-has-sixty-three-octets-taking-max-label-length"));
  assert(hsk_dns_name_dirty("hel!lo"));
  assert(hsk_dns_name_dirty("-hello"));
  assert(hsk_dns_name_dirty("hello_"));
  assert(hsk_dns_name_dirty("1@1"));
  assert(hsk_dns_name_dirty("x\\000y"));
  assert(hsk_dns_name_dirty("H&ELLO"));
  assert(hsk_dns_name_dirty("3 3"));
  assert(hsk_dns_name_dirty("this-domain-name-has-sixtyfour-octets-exceeding-max-label-length"));
}

int
main() {
  printf("Testing hnsd...\n");
  test_base32();
  test_pointer_to_ip();
  test_name_dirty();

  printf("ok\n");

  return 0;
}
