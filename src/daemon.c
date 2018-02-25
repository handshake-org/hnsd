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

#include "hsk.h"
#include "pool.h"
#include "ns.h"
#include "rs.h"
#include "uv.h"
#include "utils.h"

/*
 * Main
 */

int
main() {
  struct sockaddr_storage ns_addr_;
  struct sockaddr_storage rs_addr_;
  struct sockaddr *ns_addr = (struct sockaddr *)&ns_addr_;
  struct sockaddr *rs_addr = (struct sockaddr *)&rs_addr_;
  int32_t rc = HSK_SUCCESS;
  uv_loop_t *loop = NULL;
  hsk_pool_t *pool = NULL;
  hsk_ns_t *ns = NULL;
  hsk_rs_t *rs = NULL;

  if (!hsk_string2inet("127.0.0.1", ns_addr, HSK_NS_PORT)) {
    rc = HSK_EBADARGS;
    goto done;
  }

  if (!hsk_string2inet("127.0.0.1", rs_addr, HSK_RS_PORT)) {
    rc = HSK_EBADARGS;
    goto done;
  }

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

  ns = hsk_ns_alloc(loop, pool);

  if (!ns) {
    fprintf(stderr, "failed initializing ns\n");
    rc = HSK_ENOMEM;
    goto done;
  }

  rs = hsk_rs_alloc(loop, ns_addr);

  if (!rs) {
    fprintf(stderr, "failed initializing rns\n");
    rc = HSK_ENOMEM;
    goto done;
  }

  rc = hsk_pool_open(pool);

  if (rc != HSK_SUCCESS) {
    fprintf(stderr, "failed opening pool: %d\n", rc);
    goto done;
  }

  rc = hsk_ns_open(ns, ns_addr);

  if (rc != HSK_SUCCESS) {
    fprintf(stderr, "failed opening ns: %d\n", rc);
    goto done;
  }

  rc = hsk_rs_open(rs, rs_addr);

  if (rc != HSK_SUCCESS) {
    fprintf(stderr, "failed opening rns: %d\n", rc);
    goto done;
  }

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
