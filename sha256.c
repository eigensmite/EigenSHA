
#include "sha256.h"

static const uint32_t H_0_224[8] = { 
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};

static const uint32_t H_0_256[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

void sha256_init(sha256_ctx *ctx) {
    for (int i = 0; i < 8; i++) {
        ctx->hash[i] = H_0_256[i];
    }
    ctx->pos = 0;
    ctx->len = 0;
    ctx->out = 32;
}

void sha224_init(sha224_ctx *ctx) {
    for (int i = 0; i < 8; i++) {
        ctx->hash[i] = H_0_224[i];
    }
    ctx->pos = 0;
    ctx->len = 0;
    ctx->out = 28;
}

void sha256_update(sha256_ctx *ctx, uint8_t *data, size_t len) {
    while (len > 0) {
        size_t take = 512/8 - ctx->pos;
        if (take > len) take = len;
        //printf("copy\n");
        memcpy(ctx->buf + ctx->pos, data, take);
        data += take;
        ctx->pos += take;
        ctx->len += take;
        len -= take;
        if (ctx->pos == 512/8) {
            update_intermediate_hash_256(ctx->hash, ctx->buf);
            ctx->pos = 0;
        }
    }
}

void sha224_update(sha224_ctx *ctx, uint8_t *data, size_t len) {
    sha256_update((sha256_ctx *)ctx, data, len);
}


void sha256_finalize(sha256_ctx *ctx) {
    int zero_bits = 448 - (8*ctx->len % 512) - 1;
    // printf("zero bits %d\n", zero_bits);
    if (zero_bits < 0) {
        memset(ctx->buf + ctx->pos, 0x00, 512/8 - ctx->pos);
        ctx->buf[ctx->pos] = 0x80;
        update_intermediate_hash_256(ctx->hash, ctx->buf);
        ctx->pos = 0;
    }    
    memset(ctx->buf + ctx->pos, 0x00, 512/8 - ctx->pos);
    if (zero_bits >= 0) ctx->buf[ctx->pos] = 0x80;
    ((uint64_t *)ctx->buf)[7] = __builtin_bswap64(ctx->len*8ULL);
    update_intermediate_hash_256(ctx->hash, ctx->buf);
    ctx->pos = 0;
}

void sha224_finalize(sha224_ctx *ctx) {
    sha256_finalize((sha256_ctx *)ctx);
}

void sha256_extract(uint8_t hash[32], sha256_ctx *ctx) {
    for(int i = 0; i < 8; i++)
        ((uint32_t *)hash)[i] = __builtin_bswap32(ctx->hash[i]);
}

void sha224_extract(uint8_t hash[28], sha224_ctx *ctx) {
    for(int i = 0; i < 7; i++)
        ((uint32_t *)hash)[i] = __builtin_bswap32(ctx->hash[i]);
}
