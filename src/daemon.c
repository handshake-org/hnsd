#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include <sys/types.h>
#include <unistd.h>

#include "constants.h"
#include "hsk.h"
#include "pool.h"
#include "ns.h"
#include "rs.h"
#include "signals.h"
#include "uv.h"
#include "platform-net.h"

extern char *optarg;
extern int optind, opterr, optopt;

typedef struct hsk_options_s {
  char *config;
  struct sockaddr *ns_host;
  struct sockaddr_storage _ns_host;
  struct sockaddr *rs_host;
  struct sockaddr_storage _rs_host;
  struct sockaddr *ns_ip;
  struct sockaddr_storage _ns_ip;
  char *rs_config;
  uint8_t identity_key_[32];
  uint8_t *identity_key;
  char *seeds;
  int pool_size;
  char *user_agent;
  bool checkpoint;
  char *prefix;
} hsk_options_t;

static void
hsk_options_init(hsk_options_t *opt) {
  opt->config = NULL;
  opt->ns_host = (struct sockaddr *)&opt->_ns_host;
  opt->rs_host = (struct sockaddr *)&opt->_rs_host;
  opt->ns_ip = (struct sockaddr *)&opt->_ns_ip;
  assert(hsk_sa_from_string(opt->ns_host, HSK_NS_IP, HSK_NS_PORT));
  assert(hsk_sa_from_string(opt->rs_host, HSK_RS_IP, HSK_RS_PORT));
  assert(hsk_sa_from_string(opt->ns_ip, HSK_RS_A, 0));
  opt->rs_config = NULL;
  memset(opt->identity_key_, 0, sizeof(opt->identity_key_));
  opt->identity_key = NULL;
  opt->seeds = NULL;
  opt->pool_size = HSK_POOL_SIZE;
  opt->user_agent = NULL;
  opt->checkpoint = false;
  opt->prefix = NULL;
}

static void
hsk_options_uninit(hsk_options_t *opt) {
  if (opt->config) {
    free(opt->config);
    opt->config = NULL;
  }

  if (opt->rs_config) {
    free(opt->rs_config);
    opt->rs_config = NULL;
  }

  if (opt->identity_key) {
    free(opt->identity_key);
    opt->identity_key = NULL;
  }

  if (opt->seeds) {
    free(opt->seeds);
    opt->seeds = NULL;
  }

  if (opt->user_agent) {
    free(opt->user_agent);
    opt->user_agent = NULL;
  }

  if (opt->prefix) {
    free(opt->prefix);
    opt->prefix = NULL;
  }
}

static void
set_logfile(const char *logfile) {
  assert(logfile);
  freopen(logfile, "a", stdout);
  freopen(logfile, "a", stderr);
#ifdef __linux
  setlinebuf(stdout);
  setlinebuf(stderr);
#endif
}

// --daemon is not supported under MinGW (no fork() syscall)
#ifndef _WIN32
static bool
daemonize(const char *logfile) {
#ifdef __linux
  if (getppid() == 1)
    return true;
#endif

  int pid = fork();

  if (pid == -1)
    return false;

  if (pid > 0) {
    _exit(0);
    return false;
  }

#ifdef __linux
  setsid();
#endif

  fprintf(stderr, "PID: %d\n", getpid());

  freopen("/dev/null", "r", stdin);

  if (logfile) {
    set_logfile(logfile);
  } else {
    freopen("/dev/null", "w", stdout);
    freopen("/dev/null", "w", stderr);
  }

  return true;
}
#endif

static void
help(int r) {
  fprintf(stderr,
    "\n"
    PACKAGE_NAME" "PACKAGE_VERSION" ("HSK_NETWORK_NAME")\n"
    "  Copyright (c) 2018, Christopher Jeffrey <chjj@handshake.org>\n"
    "\n"
    "Usage: hnsd [options]\n"
    "\n"
    "  -c, --config <config>\n"
    "    Path to config file.\n"
    "\n"
    "  -n, --ns-host <ip[:port]>\n"
    "    IP address and port for root nameserver, e.g. 127.0.0.1:5369.\n"
    "\n"
    "  -r, --rs-host <ip[:port]>\n"
    "    IP address and port for recursive nameserver, e.g. 127.0.0.1:53.\n"
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
    "    Identity key for signing DNS responses as well as P2P messages.\n"
    "\n"
    "  -s, --seeds <seed1,seed2,...>\n"
    "    Extra seeds to connect to on the P2P network.\n"
    "    Example:\n"
    "      -s aorsxa4ylaacshipyjkfbvzfkh3jhh4yowtoqdt64nzemqtiw2whk@127.0.0.1\n"
    "\n"
    "  -l, --log-file <filename>\n"
    "    Redirect output to a log file.\n"
    "\n"
    "  -a, --user-agent <string>\n"
    "    Add supplemental user agent string in p2p version message.\n"
    "\n"
    "  -v, --version\n"
    "    Print version and network build information and exit.\n"
    "\n"
    "  -t, --checkpoint\n"
    "    Start chain sync from checkpoint.\n"
    "\n"
    "  -x, --prefix <directory name>\n"
    "    Write/read state to/from disk in given directory.\n"
    "\n"
#ifndef _WIN32
    "  -d, --daemon\n"
    "    Fork and background the process.\n"
    "\n"
#endif
    "  -h, --help\n"
    "    This help message.\n"
    "\n"
  );

  exit(r);
}

static void
parse_arg(int argc, char **argv, hsk_options_t *opt) {
  const static char *optstring = "hvtc:n:r:i:u:p:k:s:l:h:a:x:"

#ifndef _WIN32
    "d"
#endif
    ;

  const static struct option longopts[] = {
    { "version", no_argument, NULL, 'v' },
    { "config", required_argument, NULL, 'c' },
    { "ns-host", required_argument, NULL, 'n' },
    { "rs-host", required_argument, NULL, 'r' },
    { "ns-ip", required_argument, NULL, 'i' },
    { "rs-config", required_argument, NULL, 'u' },
    { "pool-size", required_argument, NULL, 'p' },
    { "identity-key", required_argument, NULL, 'k' },
    { "seeds", required_argument, NULL, 's' },
    { "log-file", required_argument, NULL, 'l' },
    { "user-agent", required_argument, NULL, 'a' },
    { "checkpoint", no_argument, NULL, 't' },
    { "prefix", required_argument, NULL, 'x' },
#ifndef _WIN32
    { "daemon", no_argument, NULL, 'd' },
#endif
    { "help", no_argument, NULL, 'h' }
  };

  int longopt_idx = -1;
  bool has_ip = false;
  char *logfile = NULL;
#ifndef _WIN32
  bool background = false;
#endif

  optind = 1;

  for (;;) {
    int o = getopt_long(argc, argv, optstring, longopts, &longopt_idx);

    if (o == -1)
      break;

    switch (o) {
      case 'v': {
        printf("%s (%s)\n", PACKAGE_VERSION, HSK_NETWORK_NAME);
        exit(0);
      }

      case 'h': {
        return help(0);
      }

      case 'c': {
        if (!optarg || strlen(optarg) == 0)
          return help(1);

        if (opt->config)
          free(opt->config);

        opt->config = strdup(optarg);

        break;
      }

      case 'n': {
        if (!optarg || strlen(optarg) == 0)
          return help(1);

        if (!hsk_sa_from_string(opt->ns_host, optarg, HSK_NS_PORT))
          return help(1);

        break;
      }

      case 'r': {
        if (!optarg || strlen(optarg) == 0)
          return help(1);

        if (!hsk_sa_from_string(opt->rs_host, optarg, HSK_RS_PORT))
          return help(1);

        break;
      }

      case 'i': {
        if (!optarg || strlen(optarg) == 0)
          return help(1);

        if (!hsk_sa_from_string(opt->ns_ip, optarg, 0))
          return help(1);

        has_ip = true;

        break;
      }

      case 'u': {
        if (!optarg || strlen(optarg) == 0)
          return help(1);

        if (opt->rs_config)
          free(opt->rs_config);

        opt->rs_config = strdup(optarg);

        break;
      }

      case 'p': {
        if (!optarg || strlen(optarg) == 0)
          return help(1);

        int size = atoi(optarg);

        if (size <= 0 || size > 1000)
          return help(1);

        opt->pool_size = size;

        break;
      }

      case 'k': {
        if (!optarg || strlen(optarg) == 0)
          return help(1);

        if (hsk_hex_decode_size(optarg) != 32)
          return help(1);

        if (!hsk_hex_decode(optarg, &opt->identity_key_[0]))
          return help(1);

        opt->identity_key = &opt->identity_key_[0];

        break;
      }

      case 's': {
        if (!optarg || strlen(optarg) == 0)
          return help(1);

        if (opt->seeds)
          free(opt->seeds);

        opt->seeds = strdup(optarg);

        break;
      }

      case 'l': {
        if (!optarg || strlen(optarg) == 0)
          return help(1);

        if (logfile)
          free(logfile);

        logfile = strdup(optarg);

        break;
      }

      case 'a': {
        if (!optarg || strlen(optarg) == 0)
          return help(1);

        if (opt->user_agent)
          free(opt->user_agent);

        opt->user_agent = strdup(optarg);

        break;
      }

      case 'x': {
        if (!optarg || strlen(optarg) == 0)
          return help(1);

        if (opt->prefix)
          free(opt->prefix);

        opt->prefix = strdup(optarg);

        break;
      }

      case 't': {

        opt->checkpoint = true;

        break;
      }

#ifndef _WIN32
      case 'd': {
        background = true;
        break;
      }
#endif

      case '?': {
        return help(1);
      }
    }
  }

  if (optind < argc)
    return help(1);

  if (!has_ip)
    hsk_sa_copy(opt->ns_ip, opt->ns_host);

#ifndef _WIN32
  if (background)
    daemonize(logfile);
  else
#endif
  {
    if (logfile)
      set_logfile(logfile);
  }

  if (logfile)
    free(logfile);
}

static bool
print_identity(const uint8_t *key) {
  hsk_ec_t *ec = hsk_ec_alloc();

  if (!ec)
    return false;

  uint8_t pub[33];

  if (!hsk_ec_create_pubkey(ec, key, pub)) {
    hsk_ec_free(ec);
    return false;
  }

  hsk_ec_free(ec);

  size_t size = hsk_base32_encode_size(pub, 33, false);
  assert(size <= 54);

  char b32[54];
  hsk_base32_encode(pub, 33, b32, false);

  printf("starting with identity key of: %s\n", b32);

  return true;
}

/*
 * Daemon
 */
typedef struct {
  hsk_signals_t *signals;
  hsk_pool_t *pool;
  hsk_ns_t *ns;
  hsk_rs_t *rs;
} hsk_daemon_t;

static void
hsk_daemon_after_close(void *data);
static void
hsk_daemon_signal_shutdown(void *data);
static void
hsk_daemon_uninit(hsk_daemon_t *data);

int
hsk_daemon_init(hsk_daemon_t *daemon, uv_loop_t *loop, hsk_options_t *opt) {
  daemon->signals = NULL;
  daemon->pool = NULL;
  daemon->ns = NULL;
  daemon->rs = NULL;

  int rc = HSK_SUCCESS;

  daemon->signals = hsk_signals_alloc(loop, (void *)daemon,
                                      hsk_daemon_signal_shutdown);

  if (!daemon->signals) {
    fprintf(stderr, "failed initializing signal handlers\n");
    rc = HSK_EFAILURE;
    goto fail;
  }

  daemon->pool = hsk_pool_alloc(loop);

  if (!daemon->pool) {
    fprintf(stderr, "failed initializing pool\n");
    rc = HSK_ENOMEM;
    goto fail;
  }

  if (opt->identity_key) {
    if (!hsk_pool_set_key(daemon->pool, opt->identity_key)) {
      fprintf(stderr, "failed setting identity key\n");
      rc = HSK_EFAILURE;
      goto fail;
    }
  }

  if (!hsk_pool_set_size(daemon->pool, opt->pool_size)) {
    fprintf(stderr, "failed setting pool size\n");
    rc = HSK_EFAILURE;
    goto fail;
  }

  if (!hsk_pool_set_seeds(daemon->pool, opt->seeds)) {
    fprintf(stderr, "failed adding seeds\n");
    rc = HSK_EFAILURE;
    goto fail;
  }

  if (!hsk_pool_set_agent(daemon->pool, opt->user_agent)) {
    fprintf(stderr, "failed adding user agent\n");
    rc = HSK_EFAILURE;
    goto fail;
  }

  daemon->ns = hsk_ns_alloc(loop, daemon->pool);

  if (!daemon->ns) {
    fprintf(stderr, "failed initializing ns\n");
    rc = HSK_ENOMEM;
    goto fail;
  }

  if (!hsk_ns_set_ip(daemon->ns, opt->ns_ip)) {
    fprintf(stderr, "failed setting ip\n");
    rc = HSK_EFAILURE;
    goto fail;
  }

  if (opt->identity_key) {
    if (!hsk_ns_set_key(daemon->ns, opt->identity_key)) {
      fprintf(stderr, "failed setting identity key\n");
      rc = HSK_EFAILURE;
      goto fail;
    }
  }

  daemon->rs = hsk_rs_alloc(loop, opt->ns_host);

  if (!daemon->rs) {
    fprintf(stderr, "failed initializing rns\n");
    rc = HSK_ENOMEM;
    goto fail;
  }

  if (opt->rs_config) {
    if (!hsk_rs_set_config(daemon->rs, opt->rs_config)) {
      fprintf(stderr, "failed setting rs config\n");
      rc = HSK_EFAILURE;
      goto fail;
    }
  }

  if (opt->identity_key) {
    if (!hsk_rs_set_key(daemon->rs, opt->identity_key)) {
      fprintf(stderr, "failed setting identity key\n");
      rc = HSK_EFAILURE;
      goto fail;
    }
  }

  return HSK_SUCCESS;

fail:
  hsk_daemon_uninit(daemon);
  return rc;
}

void
hsk_daemon_uninit(hsk_daemon_t *daemon) {
  if (!daemon)
    return;

  if (daemon->signals) {
    hsk_signals_free(daemon->signals);
    daemon->signals = NULL;
  }

  if (daemon->rs) {
    hsk_rs_free(daemon->rs);
    daemon->rs = NULL;
  }

  if (daemon->pool) {
    hsk_pool_free(daemon->pool);
    daemon->pool = NULL;
  }

  if (daemon->ns) {
    hsk_ns_free(daemon->ns);
    daemon->ns = NULL;
  }
}

int
hsk_daemon_open(hsk_daemon_t *daemon, hsk_options_t *opt) {
  int rc = HSK_SUCCESS;

  if (opt->checkpoint && HSK_CHECKPOINT != NULL) {
    // Read the hard-coded checkpoint
    uint8_t *data = (uint8_t *)HSK_CHECKPOINT;
    size_t data_len = HSK_STORE_CHECKPOINT_SIZE;
    if (!hsk_store_inject_checkpoint(&data, &data_len, &daemon->pool->chain)) {
      fprintf(stderr, "unable to inject hard-coded checkpoint\n");
      return HSK_EBADARGS;
    }
  }

  if (opt->prefix) {
    if (!hsk_store_exists(opt->prefix)) {
      fprintf(stderr, "prefix path does not exist\n");
      return HSK_EBADARGS;
    }

    // Prefix must have enough room for filename
    if (strlen(opt->prefix) + HSK_STORE_PATH_RESERVED >= HSK_STORE_PATH_MAX) {
      fprintf(stderr, "prefix path is too long\n");
      return HSK_EBADARGS;
    }

    daemon->pool->chain.prefix = opt->prefix;

    // Read the checkpoint from file
    uint8_t data[HSK_STORE_CHECKPOINT_SIZE];
    uint8_t *data_ptr = (uint8_t *)&data;
    size_t data_len = HSK_STORE_CHECKPOINT_SIZE;
    if (hsk_store_read(&data_ptr, &data_len, &daemon->pool->chain)) {
      if (!hsk_store_inject_checkpoint(
        &data_ptr,
        &data_len,
        &daemon->pool->chain
      )) {
        fprintf(stderr, "unable to inject checkpoint from file\n");
        return HSK_EBADARGS;
      }
    }
  }

  rc = hsk_pool_open(daemon->pool);

  if (rc != HSK_SUCCESS) {
    fprintf(stderr, "failed opening pool: %s\n", hsk_strerror(rc));
    return rc;
  }

  rc = hsk_ns_open(daemon->ns, opt->ns_host);

  if (rc != HSK_SUCCESS) {
    fprintf(stderr, "failed opening ns: %s\n", hsk_strerror(rc));
    return rc;
  }

  rc = hsk_rs_open(daemon->rs, opt->rs_host);

  if (rc != HSK_SUCCESS) {
    fprintf(stderr, "failed opening rns: %s\n", hsk_strerror(rc));
    return rc;
  }

  return HSK_SUCCESS;
}

// After hsk_daemon_init() is called (even if it fails), test if the daemon has
// been destroyed.
bool
hsk_daemon_destroyed(hsk_daemon_t *daemon) {
  // signals is created first, so just check that.
  return !daemon->signals;
}

void
hsk_daemon_close(hsk_daemon_t *daemon) {
  // If the daemon has already been destroyed, do nothing.
  if (hsk_daemon_destroyed(daemon))
    return;

  // Stop the recursive nameserver to shut down.  When this completes, the
  // daemon will be destroyed.
  //
  // If the close completes asynchronously, this could be called more than once
  // while the close is occurring, which has no effect.
  if (daemon->rs)
    hsk_rs_close(daemon->rs, (void *)daemon, hsk_daemon_after_close);
  else {
    // The recursive nameserver was never created, destroy now.
    hsk_daemon_after_close((void *)daemon);
  }
}

static void
hsk_daemon_after_close(void *data) {
  hsk_daemon_t *daemon = (hsk_daemon_t *)data;

  if (daemon->ns) {
    int rc = hsk_ns_close(daemon->ns);

    if (rc != HSK_SUCCESS)
      fprintf(stderr, "failed to close ns: %s\n", hsk_strerror(rc));
  }

  if (daemon->pool) {
    int rc = hsk_pool_close(daemon->pool);

    if (rc != HSK_SUCCESS)
      fprintf(stderr, "failed to close pool: %s\n", hsk_strerror(rc));
  }

  hsk_daemon_uninit(daemon);
}

static void
hsk_daemon_signal_shutdown(void *data) {
  hsk_daemon_t *daemon = (hsk_daemon_t *)data;
  hsk_daemon_close(daemon);
}

/*
 * Main
 */

int
main(int argc, char **argv) {
  hsk_options_t opt;
  hsk_options_init(&opt);

  parse_arg(argc, argv, &opt);

#ifndef _WIN32
  // Ignore SIGPIPE, remotely closed sockets are handled and shouldn't kill
  // hnsd.  (This happens a lot under Valgrind but can happen normally too.)
  signal(SIGPIPE, SIG_IGN);
#endif

  int rc = HSK_SUCCESS;
  uv_loop_t *loop = NULL;
  hsk_daemon_t daemon;

  if (opt.identity_key) {
    if (!print_identity(opt.identity_key)) {
      fprintf(stderr, "invalid identity key\n");
      rc = HSK_EFAILURE;
      goto done;
    }
  }

  loop = uv_default_loop();

  if (!loop) {
    fprintf(stderr, "failed initializing loop\n");
    rc = HSK_EFAILURE;
    goto done;
  }

  rc = hsk_daemon_init(&daemon, loop, &opt);
  if (rc != HSK_SUCCESS) {
    fprintf(stderr, "failed initializing daemon: %s\n", hsk_strerror(rc));
    goto done;
  }

  rc = hsk_daemon_open(&daemon, &opt);
  if (rc != HSK_SUCCESS) {
    fprintf(stderr, "failed starting daemon: %s\n", hsk_strerror(rc));
    goto done;
  }

  printf("starting event loop...\n");

  rc = uv_run(loop, UV_RUN_DEFAULT);

  if (rc != 0) {
    fprintf(stderr, "failed running event loop: %s\n", uv_strerror(rc));
    rc = HSK_EFAILURE;
    goto done;
  }

done:
  if (loop) {
    if (!hsk_daemon_destroyed(&daemon)) {
      hsk_daemon_close(&daemon);
      // Run the event loop until the potentially-asynchronous close completes.
      uv_run(loop, UV_RUN_DEFAULT);
    }

    uv_loop_close(loop);
  }

  hsk_options_uninit(&opt);

  return rc;
}
