/**
 * These test vectors were adapted from PowerDNS
 * https://github.com/PowerDNS/pdns/blob/master/pdns/test-dnsrecords_cc.cc
 * GNU General Public License v2.0
 */

#include "dns.h"

/*
 * Types
 */

typedef struct record_read_vector {
  uint16_t type;
  char name1[HSK_DNS_MAX_NAME_STRING];
  char name2[HSK_DNS_MAX_NAME_STRING];
  uint8_t data[HSK_DNS_MAX_NAME];
  size_t data_len;
} record_read_vector_t;

/*
 * Vectors
 */

// Serialized DNS message fragment for label compression.
static uint8_t record_read_msg[] = {
  // id, flags, qdcount, ancount (1), nscount, arcount
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
  // Answer 0 name is "xxxx.rec.test." and "rec.test." will be reused in the rd.
  0x04, 0x78, 0x78, 0x78, 0x78, 0x03, 0x72, 0x65, 0x63, 0x04, 0x74, 0x65, 0x73, 0x74, 0x00,
  // type, class, ttl, and rd size will be added dynamically in test
  // followed by rd data, from below...
};

static uint8_t record_read_msg_len = 27;

static char *record_read_msg_qname = "xxxx.rec.test.";

// Currently we only test for reading/writing names,
// other data in records is ignored (commented out for future tests).
static const record_read_vector_t record_read_vectors_valid[] = {
  // local nameserver
  {
    HSK_DNS_NS,
    "ns.rec.test.",
    "",
    "\x02ns\xc0\x11",
    5
  },

  // non-local nameserver
  {
    HSK_DNS_NS,
    "ns.example.com.",
    "",
    "\x02ns\x07""example\x03""com\x00",
    16
  },

  // local alias
  {
    HSK_DNS_CNAME,
    "name.rec.test.",
    "",
    "\x04name\xc0\x11",
    7
  },

  // non-local alias
  {
    HSK_DNS_CNAME,
    "name.example.com.",
    "",
    "\x04name\x07""example\x03""com\x00",
    18
  },

  // max label length (63)
  {
    HSK_DNS_CNAME,
    "123456789012345678901234567890123456789012345678901234567890123.example.com.",
    "",
    "\x3f""123456789012345678901234567890123456789012345678901234567890123\x07""example\x03""com\x00",
    77
  },

  // local max name length (255)
  {
    HSK_DNS_CNAME,
    "123456789012345678901234567890123456789012345678901234567890123.123456789012345678901234567890123456789012345678901234567890123.123456789012345678901234567890123456789012345678901234567890123.1234567890123456789012345678901234567890123456789012.rec.test.",
    "",
    "\x3f""123456789012345678901234567890123456789012345678901234567890123\x3f""123456789012345678901234567890123456789012345678901234567890123\x3f""123456789012345678901234567890123456789012345678901234567890123\x34""1234567890123456789012345678901234567890123456789012\xc0\x11",
    247
  },

  // non-local max name length (255)
  {
    HSK_DNS_CNAME,
    "123456789012345678901234567890123456789012345678901234567890123.123456789012345678901234567890123456789012345678901234567890123.123456789012345678901234567890123456789012345678901234567890123.1234567890123456789012345678901234567890123456789012345678901.",
    "",
    "\x3f""123456789012345678901234567890123456789012345678901234567890123\x3f""123456789012345678901234567890123456789012345678901234567890123\x3f""123456789012345678901234567890123456789012345678901234567890123\x3d""1234567890123456789012345678901234567890123456789012345678901\x00",
    255
  },

  // local names
  {
    HSK_DNS_SOA,
    "ns.rec.test.",
    "hostmaster.test.rec.",
    /*2013051201 3600 3600 604800 120*/
    "\x02ns\xc0\x11\x0ahostmaster\x04test\x03rec\x00\x77\xfc\xb9\x41\x00\x00\x0e\x10\x00\x00\x0e\x10\x00\x09\x3a\x80\x00\x00\x00\x78",
    46
  },

  // non-local names
  {
    HSK_DNS_SOA,
    "ns.example.com.",
    "hostmaster.example.com.",
    /*2013051201 3600 3600 604800 120*/
    "\x02ns\x07""example\x03""com\x00\x0ahostmaster\xc0\x28\x77\xfc\xb9\x41\x00\x00\x0e\x10\x00\x00\x0e\x10\x00\x09\x3a\x80\x00\x00\x00\x78",
    49
  },

  // local name
  {
    HSK_DNS_PTR,
    "ptr.rec.test.",
    "",
    "\x03ptr\xc0\x11",
    6
  },

  // non-local name
  {
    HSK_DNS_PTR,
    "ptr.example.com.",
    "",
    "\x03ptr\x07""example\x03""com\x00",
    17

  },

  // local name
  {
    HSK_DNS_MX,
    /*10*/
    "mx.rec.test.",
    "",
    "\x00\x0a\x02mx\xc0\x11",
    7
  },

  // non-local name
  {
    HSK_DNS_MX,
    /*20*/
    "mx.example.com.",
    "",
    "\x00\x14\x02mx\x07""example\x03""com\x00",
    18
  },

  // root label
  {
    HSK_DNS_MX,
    /*20*/
    ".",
    "",
    "\x00\x14\x00",
    3
  },

  // local name
  {
    HSK_DNS_RP,
    "admin.rec.test.",
    "admin-info.rec.test.",
    "\x05""admin\x03rec\x04test\x00\x0a""admin-info\x03rec\x04test\x00",
    37
  },

  // non-local name
  {
    HSK_DNS_RP,
    "admin.example.com.",
    "admin-info.example.com.",
    "\x05""admin\x07""example\x03""com\x00\x0a""admin-info\x07""example\x03""com\x00",
    43
  },

  // local name
  {
    HSK_DNS_SRV,
    /*10 10 5060*/
    "sip.rec.test.",
    "",
    "\x00\x0a\x00\x0a\x13\xc4\x03sip\x03rec\x04test\x00",
    20
  },

  // non-local name
  {
    HSK_DNS_SRV,
    /*10 10 5060*/
    "sip.example.com.",
    "",
    "\x00\x0a\x00\x0a\x13\xc4\x03sip\x07""example\x03""com\x00",
    24
  },

  // root name
  {
    HSK_DNS_SRV,
    /*10 10 5060*/
    ".",
    "",
    "\x00\x0a\x00\x0a\x13\xc4\x00",
    7
  },

  {
    HSK_DNS_RRSIG,
    /*SOA 8 3 300 20130523000000 20130509000000 54216*/
    "rec.test.",
    "",
    /*ecWKD/OsdAiXpbM/sgPT82KVD/WiQnnqcxoJgiH3ixHa+LOAcYU7FG7V4BRRJxLriY1e0rB2gAs3kCel9D4bzfK6wAqG4Di/eHUgHptRlaR2ycELJ4t1pjzrnuGiIzA1wM2izRmeE+Xoy1367Qu0pOz5DLzTfQITWFsB2iUzN4Y=*/
    "\x00\x06\x08\x03\x00\x00\x01\x2c\x51\x9d\x5c\x00\x51\x8a\xe7\x00\xd3\xc8\x03\x72\x65\x63\x04\x74\x65\x73\x74\x00\x79\xc5\x8a\x0f\xf3\xac\x74\x08\x97\xa5\xb3\x3f\xb2\x03\xd3\xf3\x62\x95\x0f\xf5\xa2\x42\x79\xea\x73\x1a\x09\x82\x21\xf7\x8b\x11\xda\xf8\xb3\x80\x71\x85\x3b\x14\x6e\xd5\xe0\x14\x51\x27\x12\xeb\x89\x8d\x5e\xd2\xb0\x76\x80\x0b\x37\x90\x27\xa5\xf4\x3e\x1b\xcd\xf2\xba\xc0\x0a\x86\xe0\x38\xbf\x78\x75\x20\x1e\x9b\x51\x95\xa4\x76\xc9\xc1\x0b\x27\x8b\x75\xa6\x3c\xeb\x9e\xe1\xa2\x23\x30\x35\xc0\xcd\xa2\xcd\x19\x9e\x13\xe5\xe8\xcb\x5d\xfa\xed\x0b\xb4\xa4\xec\xf9\x0c\xbc\xd3\x7d\x02\x13\x58\x5b\x01\xda\x25\x33\x37\x86",
    156
  },

  {
    HSK_DNS_NSEC,
    "a.rec.test.",
    /*A NS SOA MX AAAA RRSIG NSEC DNSKEY*/
    "",
    "\x01""a\x03rec\x04test\x00\x00\x07\x62\x01\x00\x08\x00\x03\x80",
    21
  },

  // TODO: Fix the 255-byte limit on URI record tarets
  // {
  //   HSK_DNS_URI,
  //   /*10000 1*/
  //   "\"ftp://ftp1.example.com/public\"",
  //   "",
  //   "\x27\x10\x00\x01\x66\x74\x70\x3a\x2f\x2f\x66\x74\x70\x31\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x2f\x70\x75\x62\x6c\x69\x63"
  // },
  // {
  //   HSK_DNS_URI,
  //   /*10 1*/
  //   "\"ftp://ftp1.example.com/public/with/a/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/very/long/url\"",
  //   "",
  //   "\x00\x0a\x00\x01\x66\x74\x70\x3a\x2f\x2f\x66\x74\x70\x31\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x2f\x70\x75\x62\x6c\x69\x63\x2f\x77\x69\x74\x68\x2f\x61\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x76\x65\x72\x79\x2f\x6c\x6f\x6e\x67\x2f\x75\x72\x6c"
  // }
};

// static const record_read_vector_t record_read_vectors_invalid[] = {
// // empty label, must be broken. No serilization exists for reverse test so use dummy
//   {HSK_DNS_CNAME, "name..example.com.", "", "\xff.dummy"},
// // overly large label (64), must be broken
//   {HSK_DNS_CNAME, "1234567890123456789012345678901234567890123456789012345678901234.example.com.", "", "\x40""1234567890123456789012345678901234567890123456789012345678901234\x07""example\x03""com\x00"},
// // local overly large name (256), must be broken
//   {HSK_DNS_CNAME, "123456789012345678901234567890123456789012345678901234567890123.123456789012345678901234567890123456789012345678901234567890123.123456789012345678901234567890123456789012345678901234567890123.12345678901234567890123456789012345678901234567890123.rec.test.", "", "\x3f""123456789012345678901234567890123456789012345678901234567890123\x3f""123456789012345678901234567890123456789012345678901234567890123\x3f""123456789012345678901234567890123456789012345678901234567890123\x35""12345678901234567890123456789012345678901234567890123\xc0\x11"},
// // non-local overly large name (256), must be broken
//   {HSK_DNS_CNAME, "123456789012345678901234567890123456789012345678901234567890123.123456789012345678901234567890123456789012345678901234567890123.123456789012345678901234567890123456789012345678901234567890123.12345678901234567890123456789012345678901234567890123456789012.", "", "\x3f""123456789012345678901234567890123456789012345678901234567890123\x3f""123456789012345678901234567890123456789012345678901234567890123\x3f""123456789012345678901234567890123456789012345678901234567890123\x3e""12345678901234567890123456789012345678901234567890123456789012\x00"}
// };
