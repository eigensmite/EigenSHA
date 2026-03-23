/******************************************************************************
 * eigensha.h
 *
 * Unified polymorphic interface for SHA-1, SHA-2, and SHA-3 families.
 *
 * The EigenSHA library provides two layers of polymorphism:
 * 
 * 1. Runtime: Using eigensha_ctx and enum Sha to switch algorithms at dev-time
 * or runtime via dynamic dispatch.
 *   - (FOR ALL SHA-1, SHA-2, SHA-3 VERSIONS)
 * 
 * 2. Compile-time: Using C11 _Generic selection to provide a uniform macro 
 * API (sha_init, sha_update, etc.) across different context types.
 *   - (FOR SHA-1, SHA-2 VERSIONS ONLY)
 *   - use sponge_init, sponge_update, etc., functions for 
 *       SHA-3 implementation, as found in sha3.h interface.)
 *
 * Author: eigensmite
 * Date: 2026-03-22
 *****************************************************************************/

#ifndef EIGENSHA_H
#define EIGENSHA_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "sha_ops.h"

/**
 * enum Sha - Supported EigenSHA hash algorithm identifiers.
 */
enum Sha {
    SHA_1,                                      // SHA-1
    SHA_224, SHA_256,                           // SHA-256 family
    SHA_384, SHA_512, SHA_512_224, SHA_512_256, // SHA-512 family
    SHA_3_224, SHA_3_256, SHA_3_384, SHA_3_512, // SHA3 family
    SHA_COUNT // enum count placeholder
};

/**
 * struct eigensha_ctx - Dynamic dispatch context.
 * @ops: Pointer to the virtual method table (VTable) for the chosen algorithm.
 * @ctx: Opaque pointer to the algorithm-specific internal state.
 */
typedef struct {
    const sha_ops *ops;
    void *ctx;
} eigensha_ctx;

/* --- Runtime Polymorphic API --- */

/**
 * eigensha_init - Dynamically allocate and initialize an active hash context.
 * @s:   The eigensha context to initialize.
 * @sha: The algorithm to use.
 */
void eigensha_init(eigensha_ctx *s, enum Sha sha);

/**
 * eigensha_free - Deallocate internal algorithm state.
 * 
 * NOTE: Use PER INIT, not PER CTX
 */
void eigensha_free(eigensha_ctx *s);

/**
 * eigensha_update - Add data to active context input buffer, automatically processing as buffer fills.
 *                   Can be performed sequentially while context is active.
 * 
 * @s:    The active context.
 * @data: raw byte stream added to input buffer.
 * @len:  length of raw byte stream in bytes.
 */
void eigensha_update(eigensha_ctx *s, void *data, size_t len);

/** 
 * eigensha_finalize - Pad remaining input buffer and process, finalizing context.
 * @s: The active context.
 */
void eigensha_finalize(eigensha_ctx *s) ;

/**
 * eigensha_extract - Extract raw bytes from finalzied context to buffer.
 * @hash: The output buffer.
 * @s:    The finalized context.
 */
void eigensha_extract(uint8_t *hash, eigensha_ctx *s);

/**
 * eigensha_get_hash_len - Returns the digest size in bytes for the context.
 */
size_t eigensha_get_hash_len(eigensha_ctx *s);

/**
 * eigensha_hash_to_string - Helper to convert raw bytes to a hex string.
 * 
 * Example: 
 *      char out[100]; uint8_t hash[64];
 *      eigensha_extract(hash, &s);
 *      eigensha_hash_to_string(out, hash, eigensha_get_hash_len(&s));
 *      printf("%s\n", out);
 */
void eigensha_hash_to_string(char *char_hash, uint8_t *hash, size_t hash_len);

/** Prevents accidental use of sha_init() with eigensha_ctx* **/
__attribute__((deprecated("CRITICAL WARNING: sha_init: invalid context type! Use eigensha_ctx* with eigensha_init() and eigensha_free()")))
__attribute__((unused))
static inline void no_generic_eigensha_init_implementation(void* ctx) {
    ctx = (void*)ctx;
    printf("sha_init: invalid context type! Use eigensha_ctx* with eigensha_init() and eigensha_free()\n");
    exit(1);
}

/* --- Compile-time Polymorphic API (C11 _Generic) --- */

/**
 * sha_init - Generic macro to initialize SHA-1, SHA-2 context type.
 * @ctx: Pointer to sha1_ctx, sha256_ctx, sha512_ctx.
 */
#define sha_init(ctx) _Generic((ctx), \
    eigensha_ctx*: no_generic_eigensha_init_implementation, \
    sha1_ctx*: sha1_init, \
    sha224_ctx*: sha224_init, \
    sha256_ctx*: sha256_init, \
    sha384_ctx*: sha384_init, \
    sha512_ctx*: sha512_init, \
    sha512_224_ctx*: sha512_224_init, \
    sha512_256_ctx*: sha512_256_init \
)(ctx)

#define sha_update(ctx, data, len) _Generic((ctx), \
    eigensha_ctx*: eigensha_update, \
    sha1_ctx*: sha1_update, \
    sha224_ctx*: sha224_update, \
    sha256_ctx*: sha256_update, \
    sha384_ctx*: sha384_update, \
    sha512_ctx*: sha512_update, \
    sha512_224_ctx*: sha512_224_update, \
    sha512_256_ctx*: sha512_256_update \
)(ctx, data, len)

#define sha_finalize(ctx) _Generic((ctx), \
    eigensha_ctx*: eigensha_finalize, \
    sha1_ctx*: sha1_finalize, \
    sha224_ctx*: sha224_finalize, \
    sha256_ctx*: sha256_finalize, \
    sha384_ctx*: sha384_finalize, \
    sha512_ctx*: sha512_finalize, \
    sha512_224_ctx*: sha512_224_finalize, \
    sha512_256_ctx*: sha512_256_finalize \
)(ctx)

#define sha_extract(hash, ctx) _Generic((ctx), \
    eigensha_ctx*: eigensha_extract, \
    sha1_ctx*: sha1_extract, \
    sha224_ctx*: sha224_extract, \
    sha256_ctx*: sha256_extract, \
    sha384_ctx*: sha384_extract, \
    sha512_ctx*: sha512_extract, \
    sha512_224_ctx*: sha512_224_extract, \
    sha512_256_ctx*: sha512_256_extract \
)(hash, ctx)

#endif