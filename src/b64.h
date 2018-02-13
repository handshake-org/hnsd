#ifndef _HSK_B64_H
#define _HSK_B64_H

#include <stdbool.h>
#include <stdint.h>

bool
b64_decode(const char *src, size_t len, uint8_t **out, size_t *out_len);

#endif
