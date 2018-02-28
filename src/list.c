#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "hsk-list.h"

void
hsk_list_init(hsk_list_t *list) {
  if (!list)
    assert(0 && "bad args");

  list->head = NULL;
  list->tail = NULL;
  list->size = 0;
}

void
hsk_list_uninit(hsk_list_t *list) {
  if (!list)
    assert(0 && "bad args");
}

hsk_list_t *
hsk_list_alloc(void) {
  hsk_list_t *list = malloc(sizeof(hsk_list_t));
  if (list)
    hsk_list_init(list);
  return list;
}

void
hsk_list_free(hsk_list_t *list) {
  if (!list)
    assert(0 && "bad args");

  hsk_list_uninit(list);
  free(list);
}

hsk_item_t *
hsk_list_head(hsk_list_t *list) {
  if (!list)
    assert(0 && "bad args");
  return list->head;
}

hsk_item_t *
hsk_list_tail(hsk_list_t *list) {
  if (!list)
    assert(0 && "bad args");
  return list->tail;
}

size_t
hsk_list_size(hsk_list_t *list) {
  if (!list)
    assert(0 && "bad args");
  return list->size;
}

void
hsk_list_reset(hsk_list_t *list) {
  if (!list)
    assert(0 && "bad args");

  hsk_item_t *item, *next;

  for (item = list->head; item; item = next) {
    next = item->next;
    item->prev = NULL;
    item->next = NULL;
  }

  assert(!item);

  list->head = NULL;
  list->tail = NULL;
  list->size = 0;
};

size_t
hsk_list_unshift(hsk_list_t *list, hsk_item_t *item) {
  if (!list || !item)
    assert(0 && "bad args");

  return hsk_list_insert(list, NULL, item);
}

hsk_item_t *
hsk_list_shift(hsk_list_t *list) {
  if (!list)
    assert(0 && "bad args");

  hsk_item_t *item = list->head;

  if (!item)
    return NULL;

  assert(hsk_list_remove(list, item));

  return item;
}

size_t
hsk_list_push(hsk_list_t *list, hsk_item_t *item) {
  if (!list || !item)
    assert(0 && "bad args");

  return hsk_list_insert(list, list->tail, item);
}

hsk_item_t *
hsk_list_pop(hsk_list_t *list) {
  if (!list)
    assert(0 && "bad args");

  hsk_item_t *item = list->tail;

  if (!item)
    return NULL;

  assert(hsk_list_remove(list, item));

  return item;
}

hsk_item_t *
hsk_list_get(hsk_list_t *list, int32_t index) {
  if (!list)
    assert(0 && "bad args");

  if (index < 0)
    index += list->size;

  if (index >= list->size)
    return NULL;

  hsk_item_t *item;
  int32_t i = 0;

  for (item = list->head; item; item = item->next) {
    if (i == index)
      return item;
    i += 1;
  }

  assert(0 && "bad list size");

  return NULL;
}

size_t
hsk_list_set(hsk_list_t *list, int32_t index, hsk_item_t *item) {
  if (!list || !item)
    assert(0 && "bad args");

  hsk_item_t *current = hsk_list_get(list, index);

  if (!current)
    return 0;

  return hsk_list_replace(list, current, item);
}

size_t
hsk_list_replace(hsk_list_t *list, hsk_item_t *item, hsk_item_t *new) {
  if (!list || !item || !new)
    assert(0 && "bad args");

  hsk_item_t *prev = item->prev;

  if (!hsk_list_remove(list, item))
    return 0;

  return hsk_list_insert(list, prev, new);
}

size_t
hsk_list_insert(hsk_list_t *list, hsk_item_t *prev, hsk_item_t *item) {
  if (!list || !item)
    assert(0 && "bad args");

  if (item->prev || item->next || item == list->head)
    return 0;

  assert(!item->prev);
  assert(!item->next);
  assert(item != list->head);

  if (!prev) {
    if (!list->head) {
      list->head = item;
      list->tail = item;
    } else {
      list->head->prev = item;
      item->next = list->head;
      list->head = item;
    }
    list->size += 1;
    return list->size;
  }

  assert(list->head && list->tail);

  item->next = prev->next;
  item->prev = prev;
  prev->next = item;

  if (item->next)
    item->next->prev = item;

  if (prev == list->tail)
    list->tail = item;

  list->size += 1;

  return list->size;
}

hsk_item_t *
hsk_list_remove(hsk_list_t *list, hsk_item_t *item) {
  if (!list || !item)
    assert(0 && "bad args");

  if (!item->prev && !item->next && item != list->head)
    return NULL;

  assert(item->prev || item->next || item == list->head);

  if (item->prev)
    item->prev->next = item->next;

  if (item->next)
    item->next->prev = item->prev;

  if (item == list->head)
    list->head = item->next;

  if (item == list->tail) {
    if (item->prev)
      list->tail = item->prev;
    else
      list->tail = list->head;
  }

  if (!list->head)
    assert(!list->tail);

  if (!list->tail)
    assert(!list->head);

  item->prev = NULL;
  item->next = NULL;

  list->size -= 1;

  return item;
}

void
hsk_item_init(hsk_item_t *item) {
  if (!item)
    assert(0 && "bad args");

  item->prev = NULL;
  item->next = NULL;
}

void
hsk_item_uninit(hsk_item_t *item) {
  if (!item)
    assert(0 && "bad args");
}

hsk_item_t *
hsk_item_alloc(void) {
  hsk_item_t *item = malloc(sizeof(hsk_item_t));
  if (item)
    hsk_item_init(item);
  return item;
}

void
hsk_item_free(hsk_item_t *item) {
  if (!item)
    assert(0 && "bad args");

  hsk_item_uninit(item);
  free(item);
}
