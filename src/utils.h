#ifndef _HSK_UTILS_H
#define _HSK_UTILS_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

int64_t
now(void);

size_t
hex_encode_size(size_t);

char *
hex_encode(uint8_t *, size_t, char *);

char *
hex_encode32(uint8_t *);

size_t
hex_decode_size(char *);

bool
hex_decode(char *, uint8_t *);

void *
xmalloc(size_t);

void *
xrealloc(void *, size_t);

void
label_split(char *fqdn, uint8_t *labels, int32_t *count);

int32_t
label_count(char *fqdn);

void
label_from2(char *fqdn, uint8_t *labels, int32_t count, int32_t idx, char *ret);

void
label_from(char *fqdn, int32_t idx, char *ret);

void
label_get2(char *fqdn, uint8_t *labels, int32_t count, int32_t idx, char *ret);

void
label_get(char *fqdn, int32_t idx, char *ret);
#endif
