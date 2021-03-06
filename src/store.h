#ifndef _HSK_STORE_H
#define _HSK_STORE_H

#include "uv.h"
#include "header.h"

/*
 * Types
 */

typedef struct hsk_store_s {
  uv_loop_t *loop;
  int fd;
  size_t size;
  uint8_t *map;
  size_t pos;
  char *location;
  hsk_header_t *headers ;
  uv_timer_t *timer;
} hsk_store_t;


int
hsk_store_init(hsk_store_t *store, const uv_loop_t *loop);

int hsk_store_uninit(hsk_store_t *store);

static void
hsk_store_timer(hsk_store_t *store);

int
hsk_store_open(hsk_store_t *store);

int
hsk_store_write(hsk_store_t *store, uint8_t *data, size_t len);

int
hsk_store_read(hsk_store_t *store, int height, hsk_header_t *header);

int
hsk_store_sync(hsk_store_t *store);

int
hsk_store_close(hsk_store_t *store);

void
hsk_store_free(hsk_store_t *store);

hsk_store_t *
hsk_store_alloc();
#endif
