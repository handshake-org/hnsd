#ifndef _HSK_RANDOM_H
#define _HSK_RANDOM_H

#include <stdint.h>
#include <stdbool.h>

bool
hsk_randombytes(uint8_t *dst, size_t len);
#endif
