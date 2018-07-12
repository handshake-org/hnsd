#include "constants.h"

#if HSK_NETWORK == HSK_MAIN

/*
 * Main
 */

static const char *hsk_seeds[] = {
  NULL
};

#elif HSK_NETWORK == HSK_TESTNET

/*
 * Testnet
 */

static const char *hsk_seeds[] = {
  "aoihqqagbhzz6wxg43itefqvmgda4uwtky362p22kbimcyg5fdp54@172.104.214.189",
  "ajdzrpoxsusaw4ixq4ttibxxsuh5fkkduc5qszyboidif2z25i362@173.255.209.126",
  "ajk57wutnhfdzvqwqrgab3wwh4wxoqgnkz4avbln54pgj5jwefcts@172.104.177.177",
  "am2lsmbzzxncaptqjo22jay3mztfwl33bxhkp7icfx7kmi5rvjaic@139.162.183.168"
  NULL
};

#elif HSK_NETWORK == HSK_REGTEST

/*
 * Regtest
 */

static const char *hsk_seeds[] = {
  "aorsxa4ylaacshipyjkfbvzfkh3jhh4yowtoqdt64nzemqtiw2whk@127.0.0.1",
  NULL
};

#elif HSK_NETWORK == HSK_SIMNET

/*
 * Simnet
 */

static const char *hsk_seeds[] = {
  "aorsxa4ylaacshipyjkfbvzfkh3jhh4yowtoqdt64nzemqtiw2whk@127.0.0.1",
  NULL
};

#else

/*
 * Bad Network
 */

#error "Invalid network."

#endif
