#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "libhsk.h"

const char *NAME = "forever";

static void
after_resolve(
  const char *name,
  int status,
  bool exists,
  const uint8_t *data,
  size_t data_len,
  const void *arg
) {
  hsk_ctx_t *ctx = (hsk_ctx_t *)arg;

  assert(strcmp(name, NAME) == 0);
  assert(status == 0);  // HSK_SUCCESS
  assert(exists);
  assert(data[0] == 0); // HNS resource version 0
  assert(data[1] == 1); // HSK_NS
  size_t length = 1 + 42 + 1 + 4 + 1;
  assert(memcmp(
    &data[2], 
    "\x2a""0x0001af047E9fb5dCD99E6823C900f3D8f5b2c5f4""\x04""_eth""\x00",
    length
  ) == 0);
  assert(arg);

  fprintf(stderr, "  test passed, exit...\n");
  hsk_ctx_close(ctx);
}

void *
open_ctx(void *arg) {
  hsk_ctx_t *ctx = (hsk_ctx_t *)arg;
  hsk_ctx_open(ctx);
  return NULL;
}

static void
test_libhsk() {
  // Capture stdout from thread (use stderr to log from test)
  fflush(stdout);
  int stdout_save = dup(STDOUT_FILENO);
  freopen("/dev/null", "w", stdout);

  // Create context
  hsk_ctx_t *ctx = hsk_ctx_create(1, "libhsk-test", "/tmp");

  // Run context in new thread
  pthread_t thread;
  assert(pthread_create(&thread, NULL, open_ctx, ctx) == 0);
  
  // Wait for sync
  for (;;) {
    float progress = hsk_ctx_get_sync_progress(ctx);
    fprintf(stderr, "  progress: %f\n", progress);

    if (progress > 0.999)
      break;

    sleep(1);
  }

  // Make request
  fprintf(stderr, "  requesting proof for: %s\n", NAME);
  hsk_ctx_resolve(ctx, NAME, after_resolve, ctx);

  // Restore output
  fflush(stdout);
  dup2(stdout_save, STDOUT_FILENO);
}

int
main() {
  printf("Testing libhsk...\n");

  printf(" test_libhsk\n");
  test_libhsk();

  printf("ok\n");
  return 0;
}
