
#ifndef SHA_256_H
#define SHA_256_H
#include "sha_algo.h"

typedef struct {
    uint32_t hash[8];
    uint8_t buf[64];
    size_t pos;
    uint64_t len;
    size_t out;
} sha256_ctx;

typedef struct {
    uint32_t hash[8];
    uint8_t buf[64];
    size_t pos;
    uint64_t len;
    size_t out;
} sha224_ctx;

void sha256_init(sha256_ctx *ctx);

void sha224_init(sha224_ctx *ctx);

void sha256_update(sha256_ctx *ctx, uint8_t *data, size_t len);

void sha224_update(sha224_ctx *ctx, uint8_t *data, size_t len);

void sha256_finalize(sha256_ctx *ctx);

void sha224_finalize(sha224_ctx *ctx);

void sha256_extract(uint8_t hash[32], sha256_ctx *ctx);

void sha224_extract(uint8_t hash[28], sha224_ctx *ctx);


#endif