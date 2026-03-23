/******************************************************************************
 * sha_512.h
 *
 * API for the SHA-512 family of cryptographic hash functions.
 *
 * This header provides the interface for SHA-512, SHA-384, SHA-512/256, 
 * and SHA-512/224. These algorithms share the same underlying 512-bit 
 * transformation engine but differ in initialization vectors (IV) and 
 * final truncation lengths.
 *
 * Author: eigensmite
 * Date: 2026-03-22
 *
 * Reference:
 * - NIST FIPS 180-4 Secure Hash Standard (SHS)
 *****************************************************************************/

#ifndef SHA_512_H
#define SHA_512_H

#include "sha_algo.h"

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

void sha512_init(sha512_ctx *ctx);

void sha384_init(sha384_ctx *ctx);

void sha512_256_init(sha512_256_ctx *ctx);

void sha512_224_init(sha512_224_ctx *ctx);

void sha512_update(sha512_ctx *ctx, uint8_t *data, size_t len);

void sha384_update(sha384_ctx *ctx, uint8_t *data, size_t len);

void sha512_256_update(sha512_256_ctx *ctx, uint8_t *data, size_t len);

void sha512_224_update(sha512_224_ctx *ctx, uint8_t *data, size_t len);

void sha512_finalize(sha512_ctx *ctx);

void sha384_finalize(sha384_ctx *ctx);

void sha512_256_finalize(sha512_256_ctx *ctx);

void sha512_224_finalize(sha512_224_ctx *ctx);

void sha512_extract(uint8_t hash[64], sha512_ctx *ctx);

void sha384_extract(uint8_t hash[48], sha384_ctx *ctx);

void sha512_256_extract(uint8_t hash[32], sha512_256_ctx *ctx);

void sha512_224_extract(uint8_t hash[28], sha512_224_ctx *ctx);


#endif