
#ifndef SHA_1_H
#define SHA_1_H

#include "sha_algo.h"

typedef struct {
    uint32_t hash[5];
    uint8_t buf[64];
    size_t pos;
    uint64_t len;
    size_t out;
} sha1_ctx;

void sha1_init(sha1_ctx *ctx);

void sha1_update(sha1_ctx *ctx, uint8_t *data, size_t len);

void sha1_finalize(sha1_ctx *ctx);

void sha1_extract(uint8_t hash[20], sha1_ctx *ctx);


#endif