#include <assert.h>
#include <stdio.h>

#include "resource.h"

static void
test_resource_pointer_to_ip() {
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
test_resource_to_dns() {
  printf("test_resource_to_dns\n");

  hsk_record_t rec;
  rec.type = HSK_NS;
  char *target = "\x03""ns1""\x10""nameserver""\x03""com.";
  strcpy(rec.name, target);

  hsk_resource_t res;
  res.version = 0;
  res.ttl = 6300;
  res.record_count = 1;
  res.records[0] = &rec;

  hsk_dns_msg_t *msg1;
  printf(" 62 char TLD\n");
  char *name1 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.";
  msg1 = hsk_resource_to_dns(&res, name1, HSK_DNS_NS);
  hsk_dns_rrs_t ns1 = msg1->ns;
  hsk_dns_rr_t *rr1 = ns1.items[0];
  hsk_dns_ns_rd_t *rd1 = rr1->rd;
  assert(strcmp(rr1->name, name1) == 0);
  assert(strcmp(rd1->ns, target) == 0);
  hsk_dns_msg_free(msg1);

  hsk_dns_msg_t *msg2;
  printf(" 63 char TLD\n");
  char *name2 = "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.";
  msg2 = hsk_resource_to_dns(&res, name2, HSK_DNS_NS);
  hsk_dns_rrs_t ns2 = msg2->ns;
  hsk_dns_rr_t *rr2 = ns2.items[0];
  hsk_dns_ns_rd_t *rd2 = rr2->rd;
  assert(strcmp(rr2->name, name2) == 0);
  assert(strcmp(rd2->ns, target) == 0);
  hsk_dns_msg_free(msg2);

  hsk_dns_msg_t *msg3;
  printf(" 64 char TLD (invalid)\n");
  char *name3 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.";
  msg3 = hsk_resource_to_dns(&res, name3, HSK_DNS_NS);
  assert(msg3 == NULL);
}

void
test_resource() {
  printf(" test_resource_pointer_to_ip\n");
  test_resource_pointer_to_ip();

  printf(" test_resource_to_dns\n");
  test_resource_to_dns();
}
