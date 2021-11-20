#include <assert.h>
#include "base32.h"
#include "resource.h"
#include "resource.c"
#include "dns.h"
#include "dns.c"
#include "data/name_serialization_vectors.h"
#include "data/resource_vectors.h"

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

  for (int i = 0; i < 7; i++) {
    name_serializtion_vector_t name_serializtion_vector = name_serializtion_vectors[i];

    uint8_t data[24] = {0};
    int len;

    hsk_dns_name_serialize(
      name_serializtion_vector.name,
      data,
      &len,
      NULL
    );

    printf(" %s\n", name_serializtion_vector.name);
    assert(len == name_serializtion_vector.expected_len);
    assert(memcmp(data, name_serializtion_vector.expected_data, len) == 0);
  }
}

void
test_decode_resource() {
  printf("test_decode_resource\n");

  for (int i = 0; i < 10; i++) {
    resource_vector_t resource_vector = resource_vectors[i];

    hsk_resource_t *res = NULL;
    hsk_resource_decode(
      resource_vector.data,
      resource_vector.data_len,
      &res
    );

    for (int t = 0; t < 4; t++) {
      type_vector_t type_vector = resource_vector.type_vectors[t];

      hsk_dns_msg_t *msg = NULL;
      msg = hsk_resource_to_dns(res, resource_vector.name, type_vector.type);

      printf(" %s %s \n", resource_vector.name, type_vector.type_string);
      assert(msg->an.size == type_vector.an_size);
      assert(msg->ns.size == type_vector.ns_size);
      assert(msg->ar.size == type_vector.ar_size);
    }
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
  test_decode_resource();

  printf("ok\n");

  return 0;
}
