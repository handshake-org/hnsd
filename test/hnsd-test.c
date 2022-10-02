#include <assert.h>
#include "base32.h"
#include "resource.h"
#include "resource.c"
#include "dns.h"
#include "dns.c"
#include "data/name_serialization_vectors.h"
#include "data/record_read_vectors.h"

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

    uint8_t data[HSK_DNS_MAX_NAME] = {0};
    int len = 0;

    printf(" %s\n", name_serializtion_vector.name);

    bool success = hsk_dns_name_serialize(
      name_serializtion_vector.name,
      data,
      &len,
      NULL
    );

    assert(name_serializtion_vector.success == success);

    if (!success)
      continue;

    assert(len == name_serializtion_vector.expected_len);
    assert(memcmp(data, name_serializtion_vector.expected_data, len) == 0);
  }
}

void
test_name_parse() {
  printf("test_name_parse\n");

  for (int i = 0; i < ARRAY_SIZE(name_serializtion_vectors); i++) {
    name_serializtion_vector_t name_serializtion_vector = name_serializtion_vectors[i];

    char name[HSK_DNS_MAX_NAME_STRING + 1] = "";

    printf(" %s\n", name_serializtion_vector.name);

    uint8_t *ptr = (uint8_t *)&name_serializtion_vector.expected_data;
    size_t len = name_serializtion_vector.expected_len;

    int ret = hsk_dns_name_parse(
      (uint8_t **)&ptr,
      &len,
      NULL,
      name
    );

    if (!name_serializtion_vector.parsed) {
      assert(ret == -1);
      continue;
    }

    assert(ret == strlen(name_serializtion_vector.parsed));
    assert(strcmp(name_serializtion_vector.parsed, name) == 0);
  }
}

bool
test_record_write(record_read_vector_t record_read_vector, void *rd) {
  char data[HSK_DNS_MAX_NAME_STRING] = "";
  uint8_t *ptr = (uint8_t *)data;

  // populate the compression map
  hsk_dns_cmp_t cmp;
  hsk_map_init_str_map(&cmp.map, NULL);
  cmp.msg = (uint8_t *)data;
  int len;
  bool success = hsk_dns_name_serialize(
    record_read_msg_qname,
    (uint8_t *)&data[0x0c],
    &len,
    &cmp
  );

  if (!success)
    return false;

  hsk_dns_rd_write(rd, record_read_vector.type, &ptr, &cmp);
  return strcmp(data, record_read_vector.data) == 0;
}

void
test_record_read() {
  printf("test_record_read_and_write\n");

  for (int i = 0; i < ARRAY_SIZE(record_read_vectors_valid); i++) {
    record_read_vector_t record_read_vector = record_read_vectors_valid[i];
    printf(" TYPE:%d %s\n",record_read_vector.type, record_read_vector.name1);

    // Create a message dump prefixed with query name "rec.test."
    // for label compression.
    size_t prefix_len = ARRAY_SIZE(record_read_msg);
    uint8_t msg[prefix_len + HSK_DNS_MAX_NAME_STRING];
    memcpy(msg, record_read_msg, prefix_len);
    memcpy(msg + prefix_len, record_read_vector.data, HSK_DNS_MAX_NAME_STRING);
    hsk_dns_dmp_t dmp;
    dmp.msg = msg;
    dmp.msg_len = prefix_len + HSK_DNS_MAX_NAME_STRING;

    void *rd = hsk_dns_rd_alloc(record_read_vector.type);
    size_t len = HSK_DNS_MAX_NAME_STRING; // overkill but doesn't matter
    uint8_t *ptr = (uint8_t *)record_read_vector.data;

    bool success = hsk_dns_rd_read(
      &ptr,
      &len,
      &dmp,
      rd,
      record_read_vector.type
    );

    assert(success);

    // check name reads are correct, check name writes are correct
    // only for simplest record data types (names only).
    switch (record_read_vector.type) {
      case HSK_DNS_NS: {
        hsk_dns_ns_rd_t *r = (hsk_dns_ns_rd_t *)rd;
        assert(strcmp(r->ns, record_read_vector.name1) == 0);
        assert(test_record_write(record_read_vector, rd));
        break;
      }
      case HSK_DNS_CNAME: {
        hsk_dns_cname_rd_t *r = (hsk_dns_cname_rd_t *)rd;
        assert(strcmp(r->target, record_read_vector.name1) == 0);
        assert(test_record_write(record_read_vector, rd));
        break;
      }
      case HSK_DNS_SOA: {
        hsk_dns_soa_rd_t *r = (hsk_dns_soa_rd_t *)rd;
        assert(strcmp(r->ns, record_read_vector.name1) == 0);
        assert(strcmp(r->mbox, record_read_vector.name2) == 0);
        break;
      }
      case HSK_DNS_PTR: {
        hsk_dns_ptr_rd_t *r = (hsk_dns_ptr_rd_t *)rd;
        assert(strcmp(r->ptr, record_read_vector.name1) == 0);
        assert(test_record_write(record_read_vector, rd));
        break;
      }
      case HSK_DNS_MX: {
        hsk_dns_mx_rd_t *r = (hsk_dns_mx_rd_t *)rd;
        assert(strcmp(r->mx, record_read_vector.name1) == 0);
        assert(test_record_write(record_read_vector, rd));
        break;
      }
      case HSK_DNS_RP: {
        hsk_dns_rp_rd_t *r = (hsk_dns_rp_rd_t *)rd;
        assert(strcmp(r->mbox, record_read_vector.name1) == 0);
        assert(strcmp(r->txt, record_read_vector.name2) == 0);
        break;
      }
      case HSK_DNS_SRV: {
        hsk_dns_srv_rd_t *r = (hsk_dns_srv_rd_t *)rd;
        assert(strcmp(r->target, record_read_vector.name1) == 0);
        break;
      }
      case HSK_DNS_RRSIG: {
        hsk_dns_rrsig_rd_t *r = (hsk_dns_rrsig_rd_t *)rd;
        assert(strcmp(r->signer_name, record_read_vector.name1) == 0);
        break;
      }
      case HSK_DNS_NSEC: {
        hsk_dns_nsec_rd_t *r = (hsk_dns_nsec_rd_t *)rd;
        assert(strcmp(r->next_domain, record_read_vector.name1) == 0);
        break;
      }
    }

    hsk_dns_rd_free(rd, record_read_vector.type);
  }

  for (int i = 0; i < ARRAY_SIZE(record_read_vectors_invalid); i++) {
    record_read_vector_t record_read_vector = record_read_vectors_invalid[i];
    printf(" TYPE:%d %s\n",record_read_vector.type, record_read_vector.name1);

    // Create a message dump prefixed with query name "rec.test."
    // for label compression.
    size_t prefix_len = ARRAY_SIZE(record_read_msg);
    uint8_t msg[prefix_len + HSK_DNS_MAX_NAME_STRING];
    memcpy(msg, record_read_msg, prefix_len);
    memcpy(msg + prefix_len, record_read_vector.data, HSK_DNS_MAX_NAME_STRING);
    hsk_dns_dmp_t dmp;
    dmp.msg = msg;
    dmp.msg_len = prefix_len + HSK_DNS_MAX_NAME_STRING;

    void *rd = hsk_dns_rd_alloc(record_read_vector.type);
    size_t len = HSK_DNS_MAX_NAME_STRING; // overkill but doesn't matter
    uint8_t *ptr = (uint8_t *)record_read_vector.data;

    bool success = hsk_dns_rd_read(
      &ptr,
      &len,
      &dmp,
      rd,
      record_read_vector.type
    );

    assert(!success);
    hsk_dns_rd_free(rd, record_read_vector.type);

    switch(record_read_vector.type) {
      case HSK_DNS_CNAME: {
        hsk_dns_cname_rd_t rd_cname;
        strcpy(rd_cname.target, record_read_vector.name1);
        assert(!test_record_write(record_read_vector, &rd_cname));
        break;
      }
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
  test_name_parse();
  test_record_read();

  printf("ok\n");

  return 0;
}
