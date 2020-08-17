#include "constants.h"

#if HSK_NETWORK == HSK_MAIN

/*
 * Main
 */

static const char *hsk_seeds[] = {
  "aonetsezqp4m52w4jpfq2gv3dggy2wqfwqtkfjyttgdidbvhgp5as@165.22.151.242",
  "aoihqqagbhzz6wxg43itefqvmgda4uwtky362p22kbimcyg5fdp54@172.104.214.189",
  "ajdzrpoxsusaw4ixq4ttibxxsuh5fkkduc5qszyboidif2z25i362@173.255.209.126",
  "ajk57wutnhfdzvqwqrgab3wwh4wxoqgnkz4avbln54pgj5jwefcts@172.104.177.177",
  "am2lsmbzzxncaptqjo22jay3mztfwl33bxhkp7icfx7kmi5rvjaic@139.162.183.168",
  "akimcha5bck7s344dmge6k3agtxd2txi6x4qzg3mo26spvf5bjol2@74.207.247.120",
  "ap5vuwabzwyz6akhesanada4skhetd2jsvpkwuqxzuaoovn5ez4xg@45.79.134.225",
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
  "am2lsmbzzxncaptqjo22jay3mztfwl33bxhkp7icfx7kmi5rvjaic@139.162.183.168",
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
