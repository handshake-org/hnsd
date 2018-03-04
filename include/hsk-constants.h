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
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcc\x50\x4c"
  "\x54\xd5\x88\x6f\xbd\x7d\xc2\x98\x59\x93\x19\x89\xcb"
  "\x42\x25\x22\x3b\x92\x5d\xf5\x0a\x96\x7f\xaf\xc3\x2f"
  "\x06\x2b\xde\x5d\x72\x7a\x6f\xe6\x43\x9f\xcb\x18\x50"
  "\xb8\xf6\xab\x60\x94\xc6\x88\xf5\xd8\x3b\x5d\xff\xde"
  "\x40\xb5\x52\xb8\x6d\xb6\xc3\x55\xc2\x03\x17\x0a\x2e"
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
