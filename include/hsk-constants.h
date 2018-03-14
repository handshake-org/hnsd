#ifndef _HSK_CONSTANTS_H
#define _HSK_CONSTANTS_H

#include "hsk-genesis.h"

#define HSK_MAIN 0
#define HSK_TESTNET 1
#define HSK_REGTEST 2
#define HSK_SIMNET 3

#ifndef HSK_NETWORK
#define HSK_NETWORK HSK_SIMNET
#endif

#define HSK_MAX_MESSAGE (4 * 1000 * 1000)
#define HSK_USER_AGENT "/libhsk:0.0.0/"
#define HSK_PROTO_VERSION 1
#define HSK_SERVICES 0
#define HSK_MAX_DATA_SIZE 512

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

#if HSK_NETWORK == HSK_MAIN

/*
 * Main
 */

#define HSK_NETWORK_NAME "main"
#define HSK_MAGIC 0xebf10ad8
#define HSK_PORT 12038

#define HSK_BITS 0x1f07ffff

static const uint8_t HSK_LIMIT[32] = {
  0x00, 0x07, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t HSK_CHAINWORK[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define HSK_TARGET_WINDOW 17
#define HSK_TARGET_SPACING (10 * 60 / 4)
#define HSK_TARGET_TIMESPAN (HSK_TARGET_WINDOW * HSK_TARGET_SPACING)
#define HSK_MIN_ACTUAL ((HSK_TARGET_TIMESPAN * (100 - 16)) / 100)
#define HSK_MAX_ACTUAL ((HSK_TARGET_TIMESPAN * (100 + 32)) / 100)
#define HSK_TARGET_RESET false
#define HSK_NO_RETARGETTING false
#define HSK_CUCKOO_BITS 30
#define HSK_CUCKOO_SIZE 42
#define HSK_CUCKOO_EASE 50
#define HSK_CUCKOO_LEGACY false
#define HSK_GENESIS HSK_GENESIS_MAIN

#define HSK_USE_CHECKPOINTS false
#define HSK_LAST_CHECKPOINT 0
#define HSK_MAX_TIP_AGE (24 * 60 * 60)

#elif HSK_NETWORK == HSK_TESTNET

/*
 * Testnet
 */

#define HSK_NETWORK_NAME "testnet"
#define HSK_MAGIC 0x8efa1fbe
#define HSK_PORT 13038

#define HSK_BITS 0x2007ffff

static const uint8_t HSK_LIMIT[32] = {
  0x07, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t HSK_CHAINWORK[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define HSK_TARGET_WINDOW 17
#define HSK_TARGET_SPACING (10 * 60 / 4)
#define HSK_TARGET_TIMESPAN (HSK_TARGET_WINDOW * HSK_TARGET_SPACING)
#define HSK_MIN_ACTUAL ((HSK_TARGET_TIMESPAN * (100 - 16)) / 100)
#define HSK_MAX_ACTUAL ((HSK_TARGET_TIMESPAN * (100 + 32)) / 100)
#define HSK_TARGET_RESET true
#define HSK_NO_RETARGETTING false
#define HSK_CUCKOO_BITS 30
#define HSK_CUCKOO_SIZE 42
#define HSK_CUCKOO_EASE 50
#define HSK_CUCKOO_LEGACY false
#define HSK_GENESIS HSK_GENESIS_TESTNET

#define HSK_USE_CHECKPOINTS false
#define HSK_LAST_CHECKPOINT 0
#define HSK_MAX_TIP_AGE (2 * 7 * 24 * 60 * 60)

#elif HSK_NETWORK == HSK_REGTEST

/*
 * Regtest
 */

#define HSK_NETWORK_NAME "regtest"
#define HSK_MAGIC 0xbcf173aa
#define HSK_PORT 14038

#define HSK_BITS 0x207fffff

static const uint8_t HSK_LIMIT[32] = {
  0x7f, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t HSK_CHAINWORK[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define HSK_TARGET_WINDOW 17
#define HSK_TARGET_SPACING (10 * 60 / 4)
#define HSK_TARGET_TIMESPAN (HSK_TARGET_WINDOW * HSK_TARGET_SPACING)
#define HSK_MIN_ACTUAL ((HSK_TARGET_TIMESPAN * (100 - 16)) / 100)
#define HSK_MAX_ACTUAL ((HSK_TARGET_TIMESPAN * (100 + 32)) / 100)
#define HSK_TARGET_RESET true
#define HSK_NO_RETARGETTING true
#define HSK_CUCKOO_BITS 8
#define HSK_CUCKOO_SIZE 4
#define HSK_CUCKOO_EASE 50
#define HSK_CUCKOO_LEGACY false
#define HSK_GENESIS HSK_GENESIS_REGTEST

#define HSK_USE_CHECKPOINTS false
#define HSK_LAST_CHECKPOINT 0
#define HSK_MAX_TIP_AGE (2 * 7 * 24 * 60 * 60)

#elif HSK_NETWORK == HSK_SIMNET

/*
 * Simnet
 */

#define HSK_NETWORK_NAME "simnet"
#define HSK_MAGIC 0x473bd012
#define HSK_PORT 15038

#define HSK_BITS 0x207fffff

static const uint8_t HSK_LIMIT[32] = {
  0x7f, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t HSK_CHAINWORK[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define HSK_TARGET_WINDOW 17
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
#define HSK_GENESIS HSK_GENESIS_SIMNET

#define HSK_USE_CHECKPOINTS false
#define HSK_LAST_CHECKPOINT 0
#define HSK_MAX_TIP_AGE (2 * 7 * 24 * 60 * 60)

#else

/*
 * Bad Network
 */

#error "Invalid network."

#endif

#endif
