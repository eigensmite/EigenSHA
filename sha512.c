
#include "sha512.h"

static const uint64_t H_0_384[8] = {
    0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
    0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
    0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
};

static const uint64_t H_0_512[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint64_t H_0_512_224[8] = {
    0x8C3D37C819544DA2ULL, 0x73E1996689DCD4D6ULL,
    0x1DFAB7AE32FF9C82ULL, 0x679DD514582F9FCFULL,
    0x0F6D2B697BD44DA8ULL, 0x77E36F7304C48942ULL,
    0x3F9D85A86A1D36C8ULL, 0x1112E6AD91D692A1ULL
};

static const uint64_t H_0_512_256[8] = {
    0x22312194FC2BF72CULL, 0x9F555FA3C84C64C2ULL,
    0x2393B86B6F53B151ULL, 0x963877195940EABDULL,
    0x96283EE2A88EFFE3ULL, 0xBE5E1E2553863992ULL,
    0x2B0199FC2C85B8AAULL, 0x0EB72DDC81C52CA2ULL
};

void sha512_init(sha512_ctx *ctx) {
    for (int i = 0; i < 8; i++) {
        ctx->hash[i] = H_0_512[i];
    }
    ctx->pos = 0;
    ctx->len = 0;
    ctx->out = 64;
}

void sha384_init(sha384_ctx *ctx) {
    for (int i = 0; i < 8; i++) {
        ctx->hash[i] = H_0_384[i];
    }
    ctx->pos = 0;
    ctx->len = 0;
    ctx->out = 48;
}

void sha512_256_init(sha512_256_ctx *ctx) {
    for (int i = 0; i < 8; i++) {
        ctx->hash[i] = H_0_512_256[i];
    }
    ctx->pos = 0;
    ctx->len = 0;
    ctx->out = 32;
}

void sha512_224_init(sha512_224_ctx *ctx) {
    for (int i = 0; i < 8; i++) {
        ctx->hash[i] = H_0_512_224[i];
    }
    ctx->pos = 0;
    ctx->len = 0;
    ctx->out = 28;
}

void sha512_update(sha512_ctx *ctx, uint8_t *data, size_t len) {
    while (len > 0 ) {
        size_t take = 1024/8 - ctx->pos;
        if (take > len) take = len;
        memcpy(ctx->buf + ctx->pos, data, take);
        data += take;
        ctx->pos += take;
        ctx->len += take;
        len -= take;
        if (ctx->pos == 1024/8) {
            update_intermediate_hash_512(ctx->hash, ctx->buf);
            ctx->pos = 0;
        }
    }
}

void sha384_update(sha384_ctx *ctx, uint8_t *data, size_t len) {
    sha512_update((sha512_ctx *)ctx, data, len);
}

void sha512_256_update(sha512_256_ctx *ctx, uint8_t *data, size_t len) {
    sha512_update((sha512_ctx *)ctx, data, len);
}

void sha512_224_update(sha512_224_ctx *ctx, uint8_t *data, size_t len) {
    sha512_update((sha512_ctx *)ctx, data, len);
}


void sha512_finalize(sha512_ctx *ctx) {
    int zero_bits = 896 - (8*ctx->len % 1024) - 1;
    if (zero_bits < 0) {
        memset(ctx->buf + ctx->pos, 0x00, 1024/8 - ctx->pos);
        ctx->buf[ctx->pos] = 0x80;
        update_intermediate_hash_512(ctx->hash, ctx->buf);
        ctx->pos = 0;
    }
    memset(ctx->buf + ctx->pos, 0x00, 1024/8 - ctx->pos);
    if (zero_bits >= 0) ctx->buf[ctx->pos] = 0x80;
    ((__uint128_t *)ctx->buf)[7] = __builtin_bswap128(ctx->len*8ULL);
    update_intermediate_hash_512(ctx->hash, ctx->buf);
    ctx->pos = 0;
}

void sha384_finalize(sha384_ctx *ctx) {
    sha512_finalize((sha512_ctx *)ctx);
}

void sha512_256_finalize(sha512_256_ctx *ctx) {
    sha512_finalize((sha512_ctx *)ctx);
}

void sha512_224_finalize(sha512_224_ctx *ctx) {
    sha512_finalize((sha512_ctx *)ctx);
}




void sha512_extract(uint8_t hash[64], sha512_ctx *ctx) {
    for (int i = 0; i < 8; i++)
        ((uint64_t *)hash)[i] = __builtin_bswap64(ctx->hash[i]);
}

void sha384_extract(uint8_t hash[48], sha384_ctx *ctx) {
    for (int i = 0; i < 6; i++)
        ((uint64_t *)hash)[i] = __builtin_bswap64(ctx->hash[i]);
}

void sha512_256_extract(uint8_t hash[32], sha512_256_ctx *ctx) {
    for (int i = 0; i < 4; i++)
        ((uint64_t *)hash)[i] = __builtin_bswap64(ctx->hash[i]);
}

void sha512_224_extract(uint8_t hash[28], sha512_224_ctx *ctx) {
    for (int i = 0; i < 3; i++)
        ((uint64_t *)hash)[i] = __builtin_bswap64(ctx->hash[i]);
    ((uint32_t *)hash)[6] = __builtin_bswap64(ctx->hash[3]);
}


