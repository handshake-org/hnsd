#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "utils.h"
#include "error.h"
#include "header.h"
#include "store.h"

int
hsk_store_init(hsk_store_t *store, const uv_loop_t *loop) {
  store->loop = (uv_loop_t *)loop;
  store->fd = -1;
  store->map = NULL;
  store->location = "/tmp/hnsd.bin";
  store->headers = malloc(sizeof(hsk_store_t));
  store->timer = NULL;
}

int hsk_store_uninit(hsk_store_t *store) {
  store->map = NULL;
  store->location = NULL;
  store->headers = NULL;
  if (munmap(store->map, store->size) == -1)
  {
    close(store->fd);
    return HSK_EFAILURE;
  }
}

static void
after_timer(uv_timer_t *timer) {
  hsk_store_t *store = (hsk_store_t *)timer->data;
  assert(store);
  hsk_store_timer(store);
}

static void
hsk_store_timer(hsk_store_t *store) {
  hsk_store_sync(store);
}

int
hsk_store_open(hsk_store_t *store) {
  store->fd = open(store->location, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600);

  if (store->fd == -1)
  {
    return HSK_EFAILURE;
  }

   store->size = 65536 * 236 + 1;

  if (lseek(store->fd, store->size-1, SEEK_SET) == -1)
  {
    close(store->fd);
    return HSK_EFAILURE;
  }

  if (write(store->fd, "", 1) == -1)
  {
    close(store->fd);
    return HSK_EFAILURE;
  }

  store->map = mmap(0, store->size, PROT_READ | PROT_WRITE, MAP_SHARED, store->fd, 0);
  if (store->map == MAP_FAILED)
  {
    close(store->fd);
    return HSK_EFAILURE;
  }

  store->timer = malloc(sizeof(uv_timer_t));
  if (!store->timer)
    return HSK_ENOMEM;

  store->timer->data = (void *)store;

  if (uv_timer_init(store->loop, store->timer) != 0)
    return HSK_EFAILURE;

  if (uv_timer_start(store->timer, after_timer, 3000, 3000) != 0)
    return HSK_EFAILURE;

  return HSK_SUCCESS;
}

int
hsk_store_write(hsk_store_t *store, uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    store->map[i+store->pos] = data[i];
  }
  store->pos += len;
}

int
hsk_store_read(hsk_store_t *store, int height, hsk_header_t *header) {
  uint8_t *data = malloc(236);
  for (size_t i = 0; i < 236; i++) {
    data[i] = store->map[i + height*236];
  }
  hsk_header_decode(data, 236, header);
  free(data);
}

int
hsk_store_sync(hsk_store_t *store) {
  if(msync(store->map, store->size, MS_SYNC) == -1)
  {
    close(store->map);
    return HSK_EFAILURE;
  }
}

int
hsk_store_close(hsk_store_t *store) {
  close(store->fd);

  if (uv_timer_stop(store->timer) != 0)
    return HSK_EFAILURE;

  hsk_uv_close_free((uv_handle_t*)store->timer);
  return HSK_SUCCESS;
}

void
hsk_store_free(hsk_store_t *store) {
  if (!store)
    return;

  hsk_store_uninit(store);
  free(store);
}

hsk_store_t *
hsk_store_alloc(const uv_loop_t *loop) {
  hsk_store_t *store = malloc(sizeof(hsk_store_t));

  if (!store)
    return NULL;

  if (hsk_store_init(store, loop) != HSK_SUCCESS) {
    hsk_store_free(store);
    return NULL;
  }

  return store;
}
