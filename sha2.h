

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sha3.h"

enum Sha {
    SHA_1, SHA_224, SHA_256, SHA_384, SHA_512, SHA_512_224, SHA_512_256, SHA_3_224, SHA_3_256, SHA_3_384, SHA_3_512, SHA_COUNT
};

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

#define DEFINE_SHA_WRAPPERS(name, ctx_type)                             \
    void name##_init_wrap(void *ctx) {                                  \
        name##_init((ctx_type*)ctx);                                    \
    }                                                                   \
                                                                        \
    void name##_update_wrap(void *ctx, uint8_t *data, size_t len) {     \
        name##_update((ctx_type*)ctx, data, len);                       \
    }                                                                   \
                                                                        \
    void name##_finalize_wrap(void *ctx) {                              \
        name##_finalize((ctx_type*)ctx);                                \
    }                                                                   \
                                                                        \
    void name##_extract_wrap(uint8_t *hash, void *ctx) {                \
        name##_extract(hash, (ctx_type*)ctx);                           \
    }

#define DEFINE_SHA_3_WRAPPERS(name, sha3_param_set)                     \
    void name##_init_wrap(void *ctx) {                                  \
        sponge_init((sponge_ctx*)ctx, sha3_param_set##_param_set);      \
    }                                                                   \
                                                                        \
    void name##_update_wrap(void *ctx, uint8_t *data, size_t len) {     \
        sponge_absorb((sponge_ctx*)ctx, data, len);                     \
    }                                                                   \
                                                                        \
    void name##_finalize_wrap(void *ctx) {                              \
        sponge_pad((sponge_ctx*)ctx);                                   \
    }                                                                   \
                                                                        \
    void name##_extract_wrap(uint8_t *hash, void *ctx) {                \
        sponge_squeeze(hash, (sponge_ctx*)ctx);                         \
    }

typedef struct {
    void (*init)    (void *ctx);
    void (*update)  (void *ctx, uint8_t *data, size_t len);
    void (*finalize)(void *ctx);
    void (*extract) (uint8_t *hash, void *ctx); 
    size_t ctx_size;
    size_t hash_size;
} sha_ops;

#define DEFINE_SHA_OPS(name, ctx_type, out)      \
    {                                            \
        .init = name##_init_wrap,                \
        .update = name##_update_wrap,            \
        .finalize = name##_finalize_wrap,        \
        .extract = name##_extract_wrap,          \
        .ctx_size = sizeof(ctx_type),            \
        .hash_size = (size_t) out                \
    }

#define DEFINE_SHA_3_OPS(name, out)              \
    {                                            \
        .init = name##_init_wrap,                \
        .update = name##_update_wrap,            \
        .finalize = name##_finalize_wrap,        \
        .extract = name##_extract_wrap,          \
        .ctx_size = sizeof(sponge_ctx),          \
        .hash_size = (size_t) out                \
    }

extern const sha_ops sha1_ops;
extern const sha_ops sha224_ops;
extern const sha_ops sha256_ops;
extern const sha_ops sha384_ops;
extern const sha_ops sha512_ops;
extern const sha_ops sha512_224_ops;
extern const sha_ops sha512_256_ops;

extern const sha_ops sha3_224_ops;
extern const sha_ops sha3_256_ops;
extern const sha_ops sha3_384_ops;
extern const sha_ops sha3_512_ops;

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
    sha_ctx*: sha_ctx_update, \
    sha1_ctx*: sha1_update, \
    sha224_ctx*: sha224_update, \
    sha256_ctx*: sha256_update, \
    sha384_ctx*: sha384_update, \
    sha512_ctx*: sha512_update, \
    sha512_224_ctx*: sha512_224_update, \
    sha512_256_ctx*: sha512_256_update \
)(ctx, data, len)

#define sha_finalize(ctx) _Generic((ctx), \
    sha_ctx*: sha_ctx_finalize, \
    sha1_ctx*: sha1_finalize, \
    sha224_ctx*: sha224_finalize, \
    sha256_ctx*: sha256_finalize, \
    sha384_ctx*: sha384_finalize, \
    sha512_ctx*: sha512_finalize, \
    sha512_224_ctx*: sha512_224_finalize, \
    sha512_256_ctx*: sha512_256_finalize \
)(ctx)

#define sha_extract(hash, ctx) _Generic((ctx), \
    sha_ctx*: sha_ctx_extract, \
    sha1_ctx*: sha1_extract, \
    sha224_ctx*: sha224_extract, \
    sha256_ctx*: sha256_extract, \
    sha384_ctx*: sha384_extract, \
    sha512_ctx*: sha512_extract, \
    sha512_224_ctx*: sha512_224_extract, \
    sha512_256_ctx*: sha512_256_extract \
)(hash, ctx)
