
/******************************************************************************
 * sha3.h
 *
 * SHA-3 (Keccak) hash function interface using the sponge construction.
 *
 * Provides:
 *   - sponge_ctx: internal state and buffer for the sponge
 *   - SHA_3: SHA-3 parameter sets (rate and output length)
 *   - Predefined SHA3-224, SHA3-256, SHA3-384, SHA3-512 parameter sets
 *   - Functions for initialization, absorption, padding, and squeezing
 *
 * Author: eigensmite
 * Date: 2026-03-14
 *
 * Reference:
 *   - FIPS 202: SHA-3 Standard
 *   - NIST Cryptographic Standards and Guidelines
 *
 * Usage:
 *   Initialize a sponge context with sponge_init(),
 *   absorb input bytes with sponge_absorb(),
 *   apply padding with sponge_pad(), and
 *   squeeze the final hash with sponge_squeeze().
 *****************************************************************************/

#ifndef SHA_3_H
#define SHA_3_H
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "keccak_f.h"

/*
 * Sponge context used by the SHA-3 implementation.
 *
 * Holds the internal state of the Keccak sponge construction and
 * the temporary input buffer used during absorption.
 *
 * state - 1600-bit Keccak state represented as 25 lanes of 64 bits
 * buf   - temporary buffer for input bytes (maximum SHA-3 rate is 200 bytes)
 * pos   - number of bytes currently stored in buf
 * rate  - sponge rate in bytes (r / 8)
 * out   - output length in bytes
 */
typedef struct {
    uint64_t state[25];
    uint8_t buf[200];
    size_t pos;
    size_t rate;
    size_t out;
} sponge_ctx;

/*
 * SHA-3 parameter set.
 *
 * Defines the algorithm parameters for a specific SHA-3 variant.
 * These values determine how the sponge operates.
 *
 * rate - number of bytes absorbed per permutation
 * out  - length of the final hash output in bytes
 */
typedef struct {
    const size_t rate;
    const size_t out;
} SHA_3;

/*
 * Predefined parameter sets for the standard SHA-3 hash functions
 * defined in FIPS 202.
 *
 * SHA3_224 - parameters for SHA3-224 (28-byte output)
 * SHA3_256 - parameters for SHA3-256 (32-byte output)
 * SHA3_384 - parameters for SHA3-384 (48-byte output)
 * SHA3_512 - parameters for SHA3-512 (64-byte output)
 */
extern const SHA_3 SHA3_224, SHA3_256, SHA3_384, SHA3_512;

/*
 * Initialize the sponge context with SHA-3 parameters.
 *
 * ctx  - sponge context
 * sha  - SHA-3 parameter set (defines rate and output size)
 */
void sponge_init(sponge_ctx *ctx, const SHA_3 sha);

/*
 * Absorb data into the sponge.
 *
 * ctx  - sponge context
 * data - input data buffer
 * len  - number of bytes to absorb
 */
void sponge_absorb(sponge_ctx *ctx, const uint8_t *data, size_t len);

/*
 * Finalize the sponge using SHA-3 padding (0x06 ... 0x80)
 * as specified in FIPS 202.
 *
 * ctx  - sponge context
 */
void sponge_pad(sponge_ctx *ctx);

/*
 * Squeeze the hash output from the sponge.
 *
 * hash - output hash buffer (of length ctx->out)
 * ctx  - sponge context
 */
void sponge_squeeze(uint8_t *hash, const sponge_ctx *ctx);

#endif
