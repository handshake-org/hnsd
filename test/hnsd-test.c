#include <assert.h>
#include "base32.h"
#include "resource.h"
#include "resource.c"
#include "dns.h"
#include "dns.c"
#include "data/resource_vectors.h"

#define ARRAY_SIZE(x) ((sizeof(x))/(sizeof(x[0])))

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
test_next_name() {
  printf("test_next_name\n");

  const char *name1 = "icecream.";
  const char *name2 = "this-domain-name-has-sixty-three-octets-taking-max-label-length.";
  char next1[HSK_DNS_MAX_NAME];
  char next2[HSK_DNS_MAX_NAME];

  next_name(name1, next1);
  next_name(name2, next2);

  assert(strcmp(
    next1,
    "icecream\\000."
  ) == 0);
  assert(strcmp(
    next2,
    "this-domain-name-has-sixty-three-octets-taking-max-label-lengti."
  ) == 0);
}

void
test_prev_name() {
  printf("test_prev_name\n");

  const char *name1 = "icecream.";
  const char *name2 = "this-domain-name-has-sixty-three-octets-taking-max-label-length.";
  char prev1[HSK_DNS_MAX_NAME];
  char prev2[HSK_DNS_MAX_NAME];

  prev_name(name1, prev1);
  prev_name(name2, prev2);

  assert(strcmp(
    prev1,
    "icecreal\\255."
  ) == 0);
  assert(strcmp(
    prev2,
    "this-domain-name-has-sixty-three-octets-taking-max-label-lengtg."
  ) == 0);
}

void
test_decode_resource() {
  printf("test_decode_resource\n");

  for (int i = 0; i < ARRAY_SIZE(resource_vectors); i++) {
    resource_vector_t resource_vector = resource_vectors[i];

    hsk_resource_t *res = NULL;
    hsk_resource_decode(
      resource_vector.data,
      resource_vector.data_len,
      &res
    );

    for (int t = 0; t < ARRAY_SIZE(resource_vector.type_vectors); t++) {
      type_vector_t type_vector = resource_vector.type_vectors[t];

      hsk_dns_msg_t *msg = NULL;
      msg = hsk_resource_to_dns(res, resource_vector.name, type_vector.type);

      printf(" %s %s \n", resource_vector.name, type_vector.type_string);
      assert(msg->an.size == type_vector.an_size);
      assert(msg->ns.size == type_vector.ns_size);
      assert(msg->ar.size == type_vector.ar_size);

      // Check `aa` bit
      assert((bool)(msg->flags & HSK_DNS_AA) == type_vector.aa);

      // Sanity check: NSEC never appears in ANSWER or ADDITIONAL
      for (int i = 0; i < msg->an.size; i++) {
        hsk_dns_rr_t *rr = msg->an.items[i];
        assert(rr->type != HSK_DNS_NSEC);
      }
      for (int i = 0; i < msg->ar.size; i++) {
        hsk_dns_rr_t *rr = msg->ar.items[i];
        assert(rr->type != HSK_DNS_NSEC);
      }

      // Check NSEC in AUTHORITY when appropriate and verify type map
      for (int i = 0; i < msg->ns.size; i++) {
        hsk_dns_rr_t *rr = msg->ns.items[i];
        if (rr->type != HSK_DNS_NSEC)
          continue;

        // NSEC is expected
        assert(type_vector.nsec);

        // Type map is correct
        hsk_dns_nsec_rd_t *rd = rr->rd;
        assert(resource_vector.type_map_len == rd->type_map_len);
        assert(memcmp(
          resource_vector.type_map,
          rd->type_map,
          rd->type_map_len
        ) == 0);
      }
    }
  }
}

int
main() {
  printf("Testing hnsd...\n");
  test_base32();
  test_pointer_to_ip();
  test_next_name();
  test_prev_name();
  test_decode_resource();

  printf("ok\n");

  return 0;
}
