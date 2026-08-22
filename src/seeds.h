#include "constants.h"

#if HSK_NETWORK == HSK_MAIN

/*
 * Main
 */

static const char *hsk_seeds[] = {
  // rithvikvibhu
  "aksygghkgmciomeldjf5sc6rs2sgn2m34zfdz4xr7z5vguqvjis4e@129.153.177.220",
  // anon
  "apt4rf2dfyelbivg63u47wykvdjtsl4kxzfdylkaae5s5ydldlnwu@159.69.46.23",
  // chjj
  "ajdzrpoxsusaw4ixq4ttibxxsuh5fkkduc5qszyboidif2z25i362@173.255.209.126",
  // chjj
  "akimcha5bck7s344dmge6k3agtxd2txi6x4qzg3mo26spvf5bjol2@74.207.247.120",
  // chjj
  "aoihqqagbhzz6wxg43itefqvmgda4uwtky362p22kbimcyg5fdp54@172.104.214.189",
  // chjj
  "am2lsmbzzxncaptqjo22jay3mztfwl33bxhkp7icfx7kmi5rvjaic@139.162.183.168",
  // chjj
  "ap5vuwabzwyz6akhesanada4skhetd2jsvpkwuqxzuaoovn5ez4xg@45.79.134.225",
  // Nathan.Woodburn/
  "ajd6wzdp34c32rymlljybvbosnx75aty4rwmtpkxshvfrqufq6vuk@103.152.197.116",
  // Nathan.Woodburn/
  "aokj73pefmtrc7ikoxqiz4nrhgrxeqnnjpv4wxekteup33duneih2@103.152.197.115",
  // Nathan.Woodburn/
  "ai7dgiwueiiwber6uhoeqfjdujxph6ueqpnaml36sicakngmnm3am@103.152.197.114",
  // Other nodes discovered by htools-org/hnsnodes
  "159.69.46.23",
  "103.152.197.115",
  "72.218.15.229",
  "91.218.58.53",
  "85.214.33.200",
  "74.207.247.120",
  "103.152.197.114",
  "44.229.138.206",
  "35.154.209.88",
  "5.161.64.49",
  "172.104.214.189",
  "129.153.177.220",
  "139.162.183.168",
  "45.79.134.225",
  "91.218.58.52",
  "47.22.22.222",
  "35.83.202.50",
  "173.255.209.126",
  "103.152.197.116",
  "91.218.58.50",
  "91.218.58.51",
  NULL
};

#elif HSK_NETWORK == HSK_TESTNET

/*
 * Testnet
 */

static const char *hsk_seeds[] = {
  "aoihqqagbhzz6wxg43itefqvmgda4uwtky362p22kbimcyg5fdp54@172.104.214.189",
  "ajdzrpoxsusaw4ixq4ttibxxsuh5fkkduc5qszyboidif2z25i362@173.255.209.126",
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
