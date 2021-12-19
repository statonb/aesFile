#ifndef _RANDOM_BYTES_H_
#define _RANDOM_BYTES_H_

#include <stdlib.h>
#include <stdint.h>

void randombytes(uint8_t *data, uint64_t n);
void randombytes_buf(uint8_t *data, size_t n);

#endif
