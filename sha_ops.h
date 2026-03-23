/******************************************************************************
 * sha_ops.h
 *
 * Virtual Method Table (VTable) definitions and wrapper macros.
 *
 * This file facilitates the internal mapping between the generic eigensha 
 * interface and the specific implementations for SHA-1, SHA-2, and SHA-3.
 *****************************************************************************/

#ifndef SHA_OPS_H
#define SHA_OPS_H

#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "sha3.h"


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


/**
 * struct sha_ops - Interface for algorithm-specific function pointers.
 * @init:     Initialize the specific context.
 * @update:   Process message data.
 * @finalize: Apply padding and finalize the hash state.
 * @extract:  Copy the final digest to a buffer.
 * @ctx_size: Size in bytes of the required internal context structure.
 * @hash_size: Size in bytes of the resulting message digest.
 */
typedef struct {
    void (*init)    (void *ctx);
    void (*update)  (void *ctx, uint8_t *data, size_t len);
    void (*finalize)(void *ctx);
    void (*extract) (uint8_t *hash, void *ctx); 
    size_t ctx_size;
    size_t hash_size;
} sha_ops;

/**
 * DEFINE_SHA_WRAPPERS - Generates void* wrapper functions for SHA-1/2.
 * @name:     The algorithm prefix (e.g., sha256).
 * @ctx_type: The specific context struct type.
 */
#define DEFINE_SHA_OPS(name, ctx_type, out)      \
    {                                            \
        .init = name##_init_wrap,                \
        .update = name##_update_wrap,            \
        .finalize = name##_finalize_wrap,        \
        .extract = name##_extract_wrap,          \
        .ctx_size = sizeof(ctx_type),            \
        .hash_size = (size_t) out                \
    }

    /**
 * DEFINE_SHA_3_WRAPPERS - Generates wrappers for the Keccak sponge engine.
 * @name:           The SHA-3 variant prefix.
 * @sha3_param_set: The specific SHA-3 parameter set (bits of security).
 */
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


#endif