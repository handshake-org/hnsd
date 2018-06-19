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
  "aoihqqagbhzz6wxg43itefqvmgda4uwtky362p22kbimcyg5fdp54@173.255.248.12",
  "ajdzrpoxsusaw4ixq4ttibxxsuh5fkkduc5qszyboidif2z25i362@66.175.217.103",
  "ajk57wutnhfdzvqwqrgab3wwh4wxoqgnkz4avbln54pgj5jwefcts@45.56.92.136",
  "am2lsmbzzxncaptqjo22jay3mztfwl33bxhkp7icfx7kmi5rvjaic@45.56.82.169",
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
