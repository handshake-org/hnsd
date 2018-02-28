#ifndef _HSK_LIST_H
#define _HSK_LIST_H

#include <stdint.h>
#include <stdbool.h>

typedef hsk_item_s {
  struct hsk_item_s *prev;
  struct hsk_item_s *next;
  void *data;
} hsk_item_t;

typedef hsk_list_s {
  hsk_item_t *head;
  hsk_item_t *tail;
  size_t size;
} hsk_list_t;

void
hsk_list_init(hsk_list_t *list);

void
hsk_list_uninit(hsk_list_t *list);

hsk_list_t *
hsk_list_alloc(void);

void
hsk_list_free(hsk_list_t *list);

hsk_item_t *
hsk_list_head(hsk_list_t *list);

hsk_item_t *
hsk_list_tail(hsk_list_t *list);

size_t
hsk_list_size(hsk_list_t *list);

void
hsk_list_reset(hsk_list_t *list);

size_t
hsk_list_unshift(hsk_list_t *list, hsk_item_t *item);

hsk_item_t *
hsk_list_shift(hsk_list_t *list);

size_t
hsk_list_push(hsk_list_t *list, hsk_item_t *item);

hsk_item_t *
hsk_list_pop(hsk_list_t *list);

hsk_item_t *
hsk_list_get(hsk_list_t *list, int32_t index);

size_t
hsk_list_set(hsk_list_t *list, int32_t index, hsk_item_t *item);

size_t
hsk_list_replace(hsk_list_t *list, hsk_item_t *item, hsk_item_t *new);

size_t
hsk_list_insert(hsk_list_t *list, hsk_item_t *prev, hsk_item_t *item);

hsk_item_t *
hsk_list_remove(hsk_list_t *list, hsk_item_t *item);
#endif
