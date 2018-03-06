#ifndef _HSK_CONSTANTS_H
#define _HSK_CONSTANTS_H

#define HSK_MAX_MESSAGE (4 * 1000 * 1000)
#define HSK_USER_AGENT "/libhsk:0.0.0/"
#define HSK_PROTO_VERSION 1
#define HSK_SERVICES 0
#define HSK_MAGIC 0x8efa1fbe
#define HSK_PORT 13038

static const uint8_t HSK_LIMIT[32] = {
  0x7f, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define HSK_BITS 0x207fffff

static const uint8_t HSK_CHAINWORK[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};

#define HSK_TARGET_WINDOW 20
#define HSK_TARGET_SPACING (10 * 60 / 4)
#define HSK_TARGET_TIMESPAN (HSK_TARGET_WINDOW * HSK_TARGET_SPACING)
#define HSK_MIN_ACTUAL ((HSK_TARGET_TIMESPAN * (100 - 16)) / 100)
#define HSK_MAX_ACTUAL ((HSK_TARGET_TIMESPAN * (100 + 32)) / 100)
#define HSK_TARGET_RESET true
#define HSK_NO_RETARGETTING false
#define HSK_CUCKOO_BITS 16
#define HSK_CUCKOO_SIZE 18
#define HSK_CUCKOO_EASE 50
#define HSK_CUCKOO_LEGACY false
#define HSK_MAX_DATA_SIZE 512

static const uint8_t HSK_GENESIS[] /* testnet */ = ""
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdb\x29\xd1"
  "\xa8\xdc\x50\x8e\xae\xaa\x97\x47\x8b\xbb\xcf\x45\x59"
  "\xc0\x1d\x8c\x51\x93\x61\x3d\xa4\xe9\x2a\xf6\xb9\x7f"
  "\x58\x9c\xfb\xd0\xba\xaf\xaa\x70\xa2\x71\x6e\x98\x9b"
  "\xa2\x73\x08\x42\x73\x3e\x16\x21\x60\x33\x07\x35\xa3"
  "\xf8\xa8\x7c\x85\x43\x00\x78\x37\xda\x03\x17\x0a\x2e"
  "\x75\x97\xb7\xb7\xe3\xd8\x4c\x05\x39\x1d\x13\x9a\x62"
  "\xb1\x57\xe7\x87\x86\xd8\xc0\x82\xf2\x9d\xcf\x4c\x11"
  "\x13\x14\x79\x7d\x49\x5a\x00\x00\x00\x00\xff\xff\x7f"
  "\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00";

#define HSK_USE_CHECKPOINTS false
#define HSK_LAST_CHECKPOINT 0
#define HSK_MAX_TIP_AGE (2 * 7 * 24 * 60 * 60)

static const uint8_t HSK_ZERO_HASH[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define HSK_NS_IP "127.0.0.1"
#define HSK_NS_PORT 5369
#define HSK_RS_IP "127.0.0.1"
#define HSK_RS_PORT 53
#define HSK_RS_A "127.0.0.1"

static const char HSK_TRUST_ANCHOR[] = ". DS 40564 8 2 "
  "BAF3CB9FC976E2CDCB49DD9E34BAA2B4C5E8EE7B1574E24ABABD9911C24FF412";

#endif
