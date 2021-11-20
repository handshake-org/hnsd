#include <assert.h>
#include "base32.h"
#include "resource.h"
#include "resource.c"
#include "dns.h"
#include "dns.c"
#include "data/name_serialization_vectors.h"

#define ARRAY_SIZE(x) ((sizeof(x))/(sizeof(x[0])))

/**
 * UTILITY
 */

void
print_array(uint8_t *arr, size_t size){
  for (int i = 0; i < size; i++) {
    printf("%02x", arr[i]);
  }
  printf("\n");
}

/*
 * TESTS
 */

void
test_base32() {
  printf("test_base32\n");

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
  printf("test_pointer_to_ip\n");

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
test_name_serialize() {
  printf("test_name_serialize\n");

  for (int i = 0; i < ARRAY_SIZE(name_serializtion_vectors); i++) {
    name_serializtion_vector_t name_serializtion_vector = name_serializtion_vectors[i];

    uint8_t data[24] = {0};
    int len = 0;

    printf(" %s\n", name_serializtion_vector.name);

    bool success = hsk_dns_name_serialize(
      name_serializtion_vector.name,
      data,
      &len,
      NULL
    );

    assert(name_serializtion_vector.success == success);
    assert(len == name_serializtion_vector.expected_len);
    assert(memcmp(data, name_serializtion_vector.expected_data, len) == 0);
  }
}

void
test_name_parse() {
  printf("test_name_parse\n");

  for (int i = 0; i < ARRAY_SIZE(name_serializtion_vectors); i++) {
    name_serializtion_vector_t name_serializtion_vector = name_serializtion_vectors[i];

    char name[255];

    if (!name_serializtion_vector.parsed)
      continue;

    printf(" %s\n", name_serializtion_vector.name);

    uint8_t *ptr = (uint8_t *)&name_serializtion_vector.expected_data;
    size_t len = name_serializtion_vector.expected_len;

    int ret = hsk_dns_name_parse(
      (uint8_t **)&ptr,
      &len,
      NULL,
      name
    );
    assert(ret == strlen(name_serializtion_vector.parsed));
    assert(strcmp(name_serializtion_vector.parsed, name) == 0);
  }
}

/*
 * TEST RUNNER
 */

int
main() {
  printf("Testing hnsd...\n");
  test_base32();
  test_pointer_to_ip();
  test_name_serialize();
  test_name_parse();

  printf("ok\n");

  return 0;
}
