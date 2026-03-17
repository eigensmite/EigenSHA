

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint32_t hash[5];
    uint8_t buf[64];
    size_t pos;
    uint64_t len;
    size_t out;
} sha1_ctx;

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

typedef struct {
    uint64_t hash[8];
    uint8_t buf[128];
    size_t pos;
    __uint128_t len;
    size_t out;
} sha512_ctx;

typedef struct {
    uint64_t hash[8];
    uint8_t buf[128];
    size_t pos;
    __uint128_t len;
    size_t out;
} sha384_ctx;


typedef struct {
    uint64_t hash[8];
    uint8_t buf[128];
    size_t pos;
    __uint128_t len;
    size_t out;
} sha512_256_ctx;

typedef struct {
    uint64_t hash[8];
    uint8_t buf[128];
    size_t pos;
    __uint128_t len;
    size_t out;
} sha512_224_ctx;



// void sha2_state_build(sha2_ctx *ctx, uint8_t *data, size_t len);

// void sha2_state_finish(sha2_ctx *ctx);

// void sha2_hash_extract(uint8_t *hash, sha2_ctx *ctx);


#define sha_init(ctx) _Generic((ctx), \
    sha1_ctx*: sha1_init, \
    sha224_ctx*: sha224_init, \
    sha256_ctx*: sha256_init, \
    sha384_ctx*: sha384_init, \
    sha512_ctx*: sha512_init, \
    sha512_224_ctx*: sha512_224_init, \
    sha512_256_ctx*: sha512_256_init \
)(ctx)

#define sha_update(ctx, data, len) _Generic((ctx), \
    sha1_ctx*: sha1_update, \
    sha224_ctx*: sha224_update, \
    sha256_ctx*: sha256_update, \
    sha384_ctx*: sha384_update, \
    sha512_ctx*: sha512_update, \
    sha512_224_ctx*: sha512_224_update, \
    sha512_256_ctx*: sha512_256_update \
)(ctx, data, len)

#define sha_finalize(ctx) _Generic((ctx), \
    sha1_ctx*: sha1_finalize, \
    sha224_ctx*: sha224_finalize, \
    sha256_ctx*: sha256_finalize, \
    sha384_ctx*: sha384_finalize, \
    sha512_ctx*: sha512_finalize, \
    sha512_224_ctx*: sha512_224_finalize, \
    sha512_256_ctx*: sha512_256_finalize \
)(ctx)

#define sha_extract(hash, ctx) _Generic((ctx), \
    sha1_ctx*: sha1_extract, \
    sha224_ctx*: sha224_extract, \
    sha256_ctx*: sha256_extract, \
    sha384_ctx*: sha384_extract, \
    sha512_ctx*: sha512_extract, \
    sha512_224_ctx*: sha512_224_extract, \
    sha512_256_ctx*: sha512_256_extract \
)(hash, ctx)
