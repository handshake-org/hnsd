#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <getopt.h>

#include "hsk.h"
#include "pool.h"
#include "ns.h"
#include "rs.h"
#include "uv.h"
#include "utils.h"

extern char *optarg;
extern int optind, opterr, optopt;

typedef struct hsk_options_s {
  char *config;
  char config_[256];
  struct sockaddr *ns_host;
  struct sockaddr_storage _ns_host;
  struct sockaddr *rs_host;
  struct sockaddr_storage _rs_host;
  struct sockaddr *ns_ip;
  struct sockaddr_storage _ns_ip;
  char *rs_config;
  char rs_config_[256];
  uint8_t identity_key_[32];
  uint8_t *identity_key;
  char *seeds;
  int32_t pool_size;
} hsk_options_t;

static void
hsk_options_init(hsk_options_t *opt) {
  opt->config = NULL;
  memset(opt->config_, 0, sizeof(opt->config_));
  opt->ns_host = (struct sockaddr *)&opt->_ns_host;
  opt->rs_host = (struct sockaddr *)&opt->_rs_host;
  opt->ns_ip = (struct sockaddr *)&opt->_ns_ip;
  assert(hsk_sa_from_string(opt->ns_host, HSK_NS_IP, HSK_NS_PORT));
  assert(hsk_sa_from_string(opt->rs_host, HSK_RS_IP, HSK_RS_PORT));
  assert(hsk_sa_from_string(opt->ns_ip, HSK_RS_A, 0));
  opt->rs_config = NULL;
  memset(opt->rs_config_, 0, sizeof(opt->config_));
  memset(opt->identity_key_, 0, sizeof(opt->identity_key_));
  opt->identity_key = NULL;
  opt->seeds = NULL;
  opt->pool_size = HSK_POOL_SIZE;
}

static void
help(int32_t r) {
  fprintf(stderr,
    "\n"
    "hskd 0.0.0\n"
    "  Copyright (c) 2018, Christopher Jeffrey (chjj@handshake.org)\n"
    "\n"
    "Usage: hskd [options]\n"
    "\n"
    "  -c, --config <config>\n"
    "    Path to config file.\n"
    "\n"
    "  -n, --ns-host <ip[@port]>\n"
    "    IP address and port for root nameserver, e.g. 127.0.0.1@5369.\n"
    "\n"
    "  -r, --rs-host <ip[@port>\n"
    "    IP address and port for recursive nameserver, e.g. 127.0.0.1@53.\n"
    "\n"
    "  -i, --ns-ip <ip>\n"
    "    Public IP for NS records in the root zone.\n"
    "\n"
    "  -u, --rs-config <config>\n"
    "    Path to unbound config file.\n"
    "\n"
    "  -p, --pool-size <size>\n"
    "    Size of peer pool.\n"
    "\n"
    "  -k, --identity-key <hex-string>\n"
    "    Identity key for signing DNS responses.\n"
    "\n"
    "  -s, --seeds <seed1,seed2,...>\n"
    "    Seeds to connect to on P2P network.\n"
    "\n"
    "  -h, --help\n"
    "    This help message.\n"
    "\n"
  );

  exit(r);
}

static void
parse_arg(int argc, char **argv, hsk_options_t *opt) {
  const static char *optstring = "c:n:r:i:u:p:k:s:h";

  const static struct option longopts[] = {
    { "config", required_argument, NULL, 'c' },
    { "ns-host", required_argument, NULL, 'n' },
    { "rs-host", required_argument, NULL, 'r' },
    { "ns-ip", required_argument, NULL, 'i' },
    { "rs-config", required_argument, NULL, 'u' },
    { "pool-size", required_argument, NULL, 'p' },
    { "identity-key", required_argument, NULL, 'k' },
    { "seeds", required_argument, NULL, 's' },
    { "help", no_argument, NULL, 'h' }
  };

  int longopt_idx = -1;
  bool has_ip = false;

  optind = 1;

  for (;;) {
    int32_t o = getopt_long(argc, argv, optstring, longopts, &longopt_idx);

    if (o == -1)
      break;

    switch (o) {
      case 'h': {
        return help(0);
      }

      case 'c': {
        if (strlen(optarg) > 255)
          return help(1);
        strcpy(opt->config_, optarg);
        opt->config = opt->config_;
        break;
      }

      case 'n': {
        if (!hsk_sa_from_string(opt->ns_host, optarg, HSK_NS_PORT))
          return help(1);
        break;
      }

      case 'r': {
        if (!hsk_sa_from_string(opt->rs_host, optarg, HSK_RS_PORT))
          return help(1);
        break;
      }

      case 'i': {
        if (!hsk_sa_from_string(opt->ns_ip, optarg, 0))
          return help(1);
        has_ip = true;
        break;
      }

      case 'u': {
        if (strlen(optarg) > 255)
          return help(1);
        strcpy(opt->rs_config_, optarg);
        opt->rs_config = opt->rs_config_;
        break;
      }

      case 'p': {
        int32_t size = atoi(optarg);

        if (size <= 0 || size > 1000)
          return help(1);

        opt->pool_size = size;

        break;
      }

      case 'k': {
        if (hsk_hex_decode_size(optarg) != 32)
          return help(1);

        if (!hsk_hex_decode(optarg, opt->identity_key_))
          return help(1);

        opt->identity_key = opt->identity_key_;

        break;
      }

      case 's': {
        opt->seeds = strdup(optarg);

        if (!opt->seeds) {
          printf("ENOMEM\n");
          exit(1);
          return;
        }

        break;
      }

      case '?': {
        return help(1);
      }
    }
  }

  if (optind < argc)
    return help(1);

  if (!has_ip)
    hsk_sa_copy(opt->ns_ip, opt->ns_host);
}

/*
 * Main
 */

int
main(int argc, char **argv) {
  hsk_options_t opt;
  hsk_options_init(&opt);

  parse_arg(argc, argv, &opt);

  int32_t rc = HSK_SUCCESS;
  uv_loop_t *loop = NULL;
  hsk_pool_t *pool = NULL;
  hsk_ns_t *ns = NULL;
  hsk_rs_t *rs = NULL;

  loop = uv_default_loop();

  if (!loop) {
    fprintf(stderr, "failed initializing loop\n");
    rc = HSK_EFAILURE;
    goto done;
  }

  pool = hsk_pool_alloc(loop);

  if (!pool) {
    fprintf(stderr, "failed initializing pool\n");
    rc = HSK_ENOMEM;
    goto done;
  }

  if (!hsk_pool_set_size(pool, opt.pool_size)) {
    fprintf(stderr, "failed setting pool size\n");
    rc = HSK_EFAILURE;
    goto done;
  }

  if (!hsk_pool_set_seeds(pool, opt.seeds)) {
    fprintf(stderr, "failed adding seeds\n");
    rc = HSK_EFAILURE;
    goto done;
  }

  ns = hsk_ns_alloc(loop, pool);

  if (!ns) {
    fprintf(stderr, "failed initializing ns\n");
    rc = HSK_ENOMEM;
    goto done;
  }

  if (!hsk_ns_set_ip(ns, opt.ns_ip)) {
    fprintf(stderr, "failed setting ip\n");
    rc = HSK_EFAILURE;
    goto done;
  }

  if (opt.identity_key) {
    if (!hsk_ns_set_key(ns, opt.identity_key)) {
      fprintf(stderr, "failed setting identity key\n");
      rc = HSK_EFAILURE;
      goto done;
    }
  }

  rs = hsk_rs_alloc(loop, opt.ns_host);

  if (!rs) {
    fprintf(stderr, "failed initializing rns\n");
    rc = HSK_ENOMEM;
    goto done;
  }

  if (opt.rs_config) {
    if (!hsk_rs_set_config(rs, opt.rs_config)) {
      fprintf(stderr, "failed setting rs config\n");
      rc = HSK_EFAILURE;
      goto done;
    }
  }

  if (opt.identity_key) {
    if (!hsk_rs_set_key(rs, opt.identity_key)) {
      fprintf(stderr, "failed setting identity key\n");
      rc = HSK_EFAILURE;
      goto done;
    }
  }

  rc = hsk_pool_open(pool);

  if (rc != HSK_SUCCESS) {
    fprintf(stderr, "failed opening pool: %d\n", rc);
    goto done;
  }

  rc = hsk_ns_open(ns, opt.ns_host);

  if (rc != HSK_SUCCESS) {
    fprintf(stderr, "failed opening ns: %d\n", rc);
    goto done;
  }

  rc = hsk_rs_open(rs, opt.rs_host);

  if (rc != HSK_SUCCESS) {
    fprintf(stderr, "failed opening rns: %d\n", rc);
    goto done;
  }

  printf("starting event loop...\n");

  rc = uv_run(loop, UV_RUN_DEFAULT);

  if (rc != 0) {
    fprintf(stderr, "failed running event loop: %d\n", rc);
    rc = HSK_EFAILURE;
    goto done;
  }

done:
  if (rs)
    hsk_rs_destroy(rs);

  if (ns)
    hsk_ns_destroy(ns);

  if (pool)
    hsk_pool_destroy(pool);

  if (loop)
    uv_loop_close(loop);

  return rc;
}
