/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef __SHA256_H_
#define __SHA256_H_

/*************************** HEADER FILES ***************************/
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/

typedef struct
{
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
    uint8_t d[SHA256_BLOCK_SIZE];
} sha256_ctx_t;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const void *data, uint32_t len);
void sha256_final(sha256_ctx_t *ctx);
void sha256_getHash(sha256_ctx_t *ctx, uint8_t *hash);
bool sha256_getHashString(sha256_ctx_t *ctx, char *hashString);
void sha256_clearContext(sha256_ctx_t *ctx);

#endif   // __SHA256_H_
