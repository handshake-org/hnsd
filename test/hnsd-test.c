#include <assert.h>
#include "base32.h"
#include "bio.h"
#include "dns.h"
#include "hash.h"
#include "req.h"
#include "resource.h"
#include "utils.h"

#include "data/record_read_vectors.h"

#define ARRAY_SIZE(x) ((sizeof(x))/(sizeof(x[0])))

void
print_array(uint8_t *arr, size_t size){
  for (int i = 0; i < size; i++) {
    printf("%02x", arr[i]);
  }
  printf("\n");
}

/*
 * base32
 */

void
test_base32() {
  printf("  test_base32\n");

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

/*
 * dns
 */

void
test_hsk_dns_label_split() {
  printf("  test_hsk_dns_label_split\n");

  const uint8_t name1[] = "\x04""hnsd""\x09""handshake""\x03""org""\x00";

  int count1 = hsk_dns_label_count((uint8_t *)&name1);
  assert(count1 == 3);

  uint8_t labels[count1];
  int count2 = hsk_dns_label_split((uint8_t *)&name1, (uint8_t *)&labels, count1);
  assert(count2 == 3);
  assert(labels[0] == 0x00);
  assert(labels[1] == 0x05);
  assert(labels[2] == 0x0f);

  uint8_t ret1[HSK_DNS_MAX_LABEL + 2];
  uint8_t ret2[HSK_DNS_MAX_LABEL + 2];
  uint8_t ret3[HSK_DNS_MAX_LABEL + 2];
  uint8_t ret4[HSK_DNS_MAX_LABEL + 2];
  // Fill arrays with 0xff to ensure no extra 0x00 is written
  memset(&ret1, 0xff, sizeof(ret1));
  memset(&ret2, 0xff, sizeof(ret2));
  memset(&ret3, 0xff, sizeof(ret3));
  memset(&ret4, 0xff, sizeof(ret4));
  int label1 = hsk_dns_label_get((uint8_t *)&name1, 0, ret1);
  int label2 = hsk_dns_label_get((uint8_t *)&name1, 1, ret2);
  int label3 = hsk_dns_label_get((uint8_t *)&name1, 2, ret3);
  int label4 = hsk_dns_label_get((uint8_t *)&name1, -1, ret4);
  assert(label1 == 4);
  assert(label2 == 9);
  assert(label3 == 3);
  assert(label4 == 3);
  // label_get writes length byte, label, and null terminator but
  // only returns the length of the label.
  // Compare one extra byte to ensure the 0xff from array init is still there.
  assert(memcmp(&ret1, "\x04""hnsd""\x00\xff", label1 + 3) == 0);
  assert(memcmp(&ret2, "\x09""handshake""\x00\xff", label2 + 3) == 0);
  assert(memcmp(&ret3, "\x03""org""\x00\xff", label3 + 3) == 0);
  assert(memcmp(&ret4, "\x03""org""\x00\xff", label4 + 3) == 0);

  uint8_t ret5[HSK_DNS_MAX_NAME];
  uint8_t ret6[HSK_DNS_MAX_NAME];
  uint8_t ret7[HSK_DNS_MAX_NAME];
  uint8_t ret8[HSK_DNS_MAX_NAME];
  memset(&ret5, 0xff, sizeof(ret5));
  memset(&ret6, 0xff, sizeof(ret6));
  memset(&ret7, 0xff, sizeof(ret7));
  memset(&ret8, 0xff, sizeof(ret8));
  int label5 = hsk_dns_label_from((uint8_t *)&name1, 0, ret5);
  int label6 = hsk_dns_label_from((uint8_t *)&name1, 1, ret6);
  int label7 = hsk_dns_label_from((uint8_t *)&name1, 2, ret7);
  int label8 = hsk_dns_label_from((uint8_t *)&name1, -1, ret8);
  assert(label5 == 20);
  assert(label6 == 15);
  assert(label7 == 5);
  assert(label8 == 5);
  // label_from writes length byte, label and null terminator and
  // returns the entire length of data written.
  // Compare one extra byte to ensure the 0xff from array init is still there.
  assert(memcmp(&ret5, "\x04""hnsd""\x09""handshake""\x03""org""\x00\xff", label5 + 1) == 0);
  assert(memcmp(&ret6, "\x09""handshake""\x03""org""\x00\xff", label6 + 1) == 0);
  assert(memcmp(&ret7, "\x03""org""\x00\xff", label7 + 1) == 0);
  assert(memcmp(&ret8, "\x03""org""\x00\xff", label8 + 1) == 0);
}

void
test_hsk_dns_msg_read() {
  printf("  test_dns_msg_read\n");

  for (int i = 0; i < ARRAY_SIZE(record_read_vectors_valid); i++) {
    record_read_vector_t record_read_vector = record_read_vectors_valid[i];
    printf("   TYPE:%02d %s\n",record_read_vector.type, record_read_vector.name1);

    // Build DNS message from test vector
    size_t meta_len = 2 + 2 + 4 + 2; // type, class, ttl, rd size
    size_t rd_len = record_read_vector.data_len;
    size_t total_len = record_read_msg_len + meta_len + rd_len;
    uint8_t data[total_len];
    uint8_t *data_ = (uint8_t *)&data;

    write_bytes(&data_, record_read_msg, record_read_msg_len);
    write_u16be(&data_, record_read_vector.type); // type
    write_u16be(&data_, HSK_DNS_IN);              // class
    write_u32be(&data_, 0x00);                    // ttl
    write_u16be(&data_, rd_len);                  // rd size
    write_bytes(&data_, (uint8_t *)record_read_vector.data, rd_len);

    // Read
    hsk_dns_msg_t *msg = hsk_dns_msg_alloc();
    data_ = (uint8_t *)&data;
    hsk_dns_msg_read(&data_, &total_len, msg);

    // Grab first answer
    hsk_dns_rr_t *rr = msg->an.items[0];

    // Read names, convert to presentation format, check
    switch (record_read_vector.type) {
      case HSK_DNS_NS: {
        hsk_dns_ns_rd_t *r = (hsk_dns_ns_rd_t *)rr->rd;
        char name1[HSK_DNS_MAX_NAME_STRING] = {0};
        assert(hsk_dns_name_to_string(r->ns, name1));
        assert(strcmp(name1, record_read_vector.name1) == 0);
        break;
      }
      case HSK_DNS_CNAME: {
        hsk_dns_cname_rd_t *r = (hsk_dns_cname_rd_t *)rr->rd;
        char name1[HSK_DNS_MAX_NAME_STRING] = {0};
        assert(hsk_dns_name_to_string(r->target, name1));
        assert(strcmp(name1, record_read_vector.name1) == 0);
        break;
      }
      case HSK_DNS_SOA: {
        hsk_dns_soa_rd_t *r = (hsk_dns_soa_rd_t *)rr->rd;
        char name1[HSK_DNS_MAX_NAME_STRING] = {0};
        assert(hsk_dns_name_to_string(r->ns, name1));
        assert(strcmp(name1, record_read_vector.name1) == 0);
        char name2[HSK_DNS_MAX_NAME_STRING] = {0};
        assert(hsk_dns_name_to_string(r->mbox, name2));
        assert(strcmp(name2, record_read_vector.name2) == 0);
        break;
      }
      case HSK_DNS_PTR: {
        hsk_dns_ptr_rd_t *r = (hsk_dns_ptr_rd_t *)rr->rd;
        char name1[HSK_DNS_MAX_NAME_STRING] = {0};
        assert(hsk_dns_name_to_string(r->ptr, name1));
        assert(strcmp(name1, record_read_vector.name1) == 0);
        break;
      }
      case HSK_DNS_MX: {
        hsk_dns_mx_rd_t *r = (hsk_dns_mx_rd_t *)rr->rd;
        char name1[HSK_DNS_MAX_NAME_STRING] = {0};
        assert(hsk_dns_name_to_string(r->mx, name1));
        assert(strcmp(name1, record_read_vector.name1) == 0);
        break;
      }
      case HSK_DNS_RP: {
        hsk_dns_rp_rd_t *r = (hsk_dns_rp_rd_t *)rr->rd;
        char name1[HSK_DNS_MAX_NAME_STRING] = {0};
        assert(hsk_dns_name_to_string(r->mbox, name1));
        assert(strcmp(name1, record_read_vector.name1) == 0);
        char name2[HSK_DNS_MAX_NAME_STRING] = {0};
        assert(hsk_dns_name_to_string(r->txt, name2));
        assert(strcmp(name2, record_read_vector.name2) == 0);
        break;
      }
      case HSK_DNS_SRV: {
        hsk_dns_srv_rd_t *r = (hsk_dns_srv_rd_t *)rr->rd;
        char name1[HSK_DNS_MAX_NAME_STRING] = {0};
        assert(hsk_dns_name_to_string(r->target, name1));
        assert(strcmp(name1, record_read_vector.name1) == 0);
        break;
      }
      case HSK_DNS_RRSIG: {
        hsk_dns_rrsig_rd_t *r = (hsk_dns_rrsig_rd_t *)rr->rd;
        char name1[HSK_DNS_MAX_NAME_STRING] = {0};
        assert(hsk_dns_name_to_string(r->signer_name, name1));
        assert(strcmp(name1, record_read_vector.name1) == 0);
        break;
      }
      case HSK_DNS_NSEC: {
        hsk_dns_nsec_rd_t *r = (hsk_dns_nsec_rd_t *)rr->rd;
        char name1[HSK_DNS_MAX_NAME_STRING] = {0};
        assert(hsk_dns_name_to_string(r->next_domain, name1));
        assert(strcmp(name1, record_read_vector.name1) == 0);
        break;
      }
    }

    hsk_dns_msg_free(msg);
  }
}

void
test_hsk_dns_msg_write(){
  printf("  test_hsk_dns_msg_write\n");
  for (int i = 0; i < ARRAY_SIZE(record_read_vectors_valid); i++) {
    record_read_vector_t record_read_vector = record_read_vectors_valid[i];

    // Build expected DNS message from test vector
    size_t meta_len = 2 + 2 + 4 + 2; // type, class, ttl, rd size
    size_t rd_len = record_read_vector.data_len;
    size_t total_len = record_read_msg_len + meta_len + rd_len;
    uint8_t data[total_len];
    uint8_t *data_ = (uint8_t *)&data;

    write_bytes(&data_, record_read_msg, record_read_msg_len);
    write_u16be(&data_, record_read_vector.type); // type
    write_u16be(&data_, HSK_DNS_IN);              // class
    write_u32be(&data_, 0x00);                    // ttl
    write_u16be(&data_, rd_len);                  // rd size
    write_bytes(&data_, (uint8_t *)record_read_vector.data, rd_len);

    // Build msg to serialize
    hsk_dns_msg_t *msg = hsk_dns_msg_alloc();
    hsk_dns_rr_t *rr = hsk_dns_rr_alloc();
    hsk_dns_name_from_string(record_read_msg_qname, rr->name);
    rr->type = record_read_vector.type;
    rr->class = HSK_DNS_IN;
    rr->ttl = 0;
    rr->rd = hsk_dns_rd_alloc(record_read_vector.type);
    hsk_dns_rrs_push(&msg->an, rr);

    // Write names, convert from presentation format
    switch (record_read_vector.type) {
      case HSK_DNS_SOA:
      case HSK_DNS_MX:
      case HSK_DNS_SRV:
      case HSK_DNS_RRSIG:
      case HSK_DNS_NSEC:
      case HSK_DNS_RP:
        // Only testing simple records with just names
        hsk_dns_msg_free(msg);
        continue;
      case HSK_DNS_NS: {
        hsk_dns_ns_rd_t *ns = rr->rd;
        hsk_dns_name_from_string(record_read_vector.name1, ns->ns);
        break;
      }
      case HSK_DNS_CNAME: {
        hsk_dns_cname_rd_t *cname = rr->rd;
        hsk_dns_name_from_string(record_read_vector.name1, cname->target);
        break;
      }
      case HSK_DNS_PTR: {
        hsk_dns_ptr_rd_t *ptr = rr->rd;
        hsk_dns_name_from_string(record_read_vector.name1, ptr->ptr);
        break;
      }
      // case HSK_DNS_RP: {
      //   hsk_dns_rp_rd_t *rp = rr->rd;
      //   hsk_dns_name_from_string(record_read_vector.name1, rp->mbox);
      //   hsk_dns_name_from_string(record_read_vector.name2, rp->txt);
      //   break;
      // }
    }

    printf("   TYPE:%02d %s\n",record_read_vector.type, record_read_vector.name1);

    uint8_t actual[total_len];
    uint8_t *actual_ = (uint8_t *)&actual;
    hsk_dns_msg_write(msg, &actual_);

    assert(memcmp(&data, &actual, total_len) == 0);

    // Also frees rr and rd
    hsk_dns_msg_free(msg);
  }
}

/*
 * hash
 */

void
test_hsk_hash_tld() {
  printf("  test_hsk_hash_tld\n");

  const uint8_t name1[10] = "\x09""handshake";
  const uint8_t expected[] = {
    0x3a, 0xa2, 0x52, 0x85, 0x76, 0xf9, 0x6b, 0xd4,
    0x0f, 0xcf, 0xf0, 0xbd, 0x6b, 0x60, 0xc4, 0x42,
    0x21, 0xd7, 0x3c, 0x43, 0xb4, 0xe4, 0x2d, 0x4b,
    0x90, 0x8e, 0xd2, 0x0a, 0x93, 0xb8, 0xd1, 0xb6
  };

  uint8_t actual[32];
  hsk_hash_tld((uint8_t *)&name1, (uint8_t *)&actual);
  assert(memcmp(&actual, &expected, 32) == 0);
}

/*
 * req
 */

void
test_hsk_dns_req_create() {
  printf("  test_hsk_dns_req_create\n");

  const uint8_t data[] = {
     0x00, 0x7b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x04, 0x68, 0x6e, 0x73,
     0x64, 0x09, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x68,
     0x61, 0x6b, 0x65, 0x03, 0x6f, 0x72, 0x67, 0x00,
     0x00, 0x10, 0x00, 0x01
  };
  const struct sockaddr addr;

  hsk_dns_req_t *req = hsk_dns_req_create(data, sizeof(data), &addr);

  assert(req->id == 123);
  assert(memcmp(req->name, "\x04""hnsd""\x09""handshake""\x03""org", 20) == 0);
  assert(req->type == 16); // TXT
  assert(req->class == 1); // IN

  free(req);
}

/*
 * resource
 */

void
test_pointer_to_ip() {
  printf("  test_pointer_to_ip\n");
  const uint8_t str4[] = "\x08""_5l6tm80""\x06""_synth""\x00";
  const uint8_t expected4[4] = {45, 77, 219, 32};
  uint8_t ip4[4];
  uint16_t family4;

  bool ret4 = pointer_to_ip(&str4[0], ip4, &family4);
  assert(ret4);
  for (int i = 0; i < 4; i++) {
    assert(ip4[i] == expected4[i]);
  }
  assert(family4 == HSK_DNS_A);

  const uint8_t str6[] = "\x1b""_400hjs000l2gol000fvvsc9cpg""\x06""_synth""\x00";
  const uint8_t expected6[16] = {
    0x20, 0x01, 0x19, 0xf0,
    0x00, 0x05, 0x45, 0x0c,
    0x54, 0x00, 0x03, 0xff,
    0xfe, 0x31, 0x2c, 0xcc
  };

  uint8_t ip6[16];
  uint16_t family6;

  bool ret6 = pointer_to_ip(&str6[0], ip6, &family6);
  assert(ret6);
  for (int i = 0; i < 16; i++) {
    assert(ip6[i] == expected6[i]);
  }
  assert(family6 == HSK_DNS_AAAA);
}


/*
 * util
 */

void test_hsk_to_lower() {
  printf("  test_hsk_to_lower\n");

  uint8_t upper[][10] =   {"\x08""EXCITING", "\x08""exciting"};
  uint8_t lower[][10] =   {"\x06""boring",   "\x06""boring"};
  uint8_t mixed[][10] =   {"\x06""InSaNe",   "\x06""insane"};
  uint8_t special[][10] = {"\x06""A!b&C ",   "\x06""a!b&c "};

  hsk_to_lower(&upper[0][0]);
  hsk_to_lower(&lower[0][0]);
  hsk_to_lower(&mixed[0][0]);
  hsk_to_lower(&special[0][0]);

  assert(memcmp(&upper[0][0], &upper[1][0], upper[0][0] + 1) == 0);
  assert(memcmp(&lower[0][0], &lower[1][0], lower[0][0] + 1) == 0);
  assert(memcmp(&mixed[0][0], &mixed[1][0], mixed[0][0] + 1) == 0);
  assert(memcmp(&special[0][0], &special[1][0], special[0][0] + 1) == 0);
}

int
main() {
  printf("Testing hnsd...\n");

  printf(" base32\n");
  test_base32();

  printf(" dns\n");
  test_hsk_dns_label_split();
  test_hsk_dns_msg_read();
  test_hsk_dns_msg_write();

  printf(" hash\n");
  test_hsk_hash_tld();

  printf(" req\n");
  test_hsk_dns_req_create();

  printf(" resource\n");
  test_pointer_to_ip();

  printf(" util\n");
  test_hsk_to_lower();

  printf("ok\n");

  return 0;
}
