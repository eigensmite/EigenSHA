
#include "sha1.h"

static const uint32_t H_0_1[5] = { 
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 
};

void sha1_init(sha1_ctx *ctx) {
    for (int i = 0; i < 5; i++) {
        ctx->hash[i] = H_0_1[i];
    }
    ctx->pos = 0;
    ctx->len = 0;
    ctx->out = 20;
}

void sha1_update(sha1_ctx *ctx, uint8_t *data, size_t len) {
    // printf("\nupdate\n");
    while (len > 0) {
        size_t take = 512/8 - ctx->pos;
        if (take > len) take = len;
        memcpy(ctx->buf + ctx->pos, data, take);
        data += take;
        ctx->pos += take;
        // printf("take: %ld\n", take);
        // printf("pos:%ld",ctx->pos);
        ctx->len += take;
        len -= take;
        if (ctx->pos == 512/8) {
            update_intermediate_hash_1(ctx->hash, ctx->buf);
            ctx->pos = 0;
        }
    }
}

void sha1_finalize(sha1_ctx *ctx) {
    int zero_bits = 448 - (8*ctx->len % 512) - 1;
    if (zero_bits < 0) {
        memset(ctx->buf + ctx->pos, 0x00, 512/8 - ctx->pos);
        ctx->buf[ctx->pos] = 0x80;
        update_intermediate_hash_1(ctx->hash, ctx->buf);
        ctx->pos = 0;
        // printf("hi\n");
    }    
    memset(ctx->buf + ctx->pos, 0x00, 512/8 - ctx->pos);
    // printf("\n%s pos:%ld\n\n",ctx->buf,ctx->pos);
    if (zero_bits >= 0) ctx->buf[ctx->pos] = 0x80;
    ((uint64_t *)ctx->buf)[7] = __builtin_bswap64(ctx->len*8ULL);
    update_intermediate_hash_1(ctx->hash, ctx->buf);
    ctx->pos = 0;
}

void sha1_extract(uint8_t hash[20], sha1_ctx *ctx) {
    for (int i = 0; i < 5; i++)
        ((uint32_t *)hash)[i] = __builtin_bswap32(ctx->hash[i]);
}
