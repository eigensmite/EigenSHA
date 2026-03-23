/******************************************************************************
 * sha_algo.h
 *
 * Core transformation functions for SHA-1, SHA-256, and SHA-512.
 *
 * This header defines the low-level block-processing engines (compression 
 * functions) used to update internal hash states. These implementations 
 * adhere to the FIPS 180-4 Secure Hash Standard (SHS).
 *
 * Author: eigensmite
 * Date: 2026-03-22
 *
 * Reference:
 * - National Institute of Standards and Technology (NIST) FIPS 180-4
 *****************************************************************************/

#ifndef SHA_ALGO_H
#define SHA_ALGO_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/**
 * update_intermediate_hash_1 - Process a single 512-bit SHA-1 message block.
 * @hash: The 160-bit internal state (5 x 32-bit words) to be updated.
 * @buf:  The 64-byte message block to be processed.
 *
 * Updates the current intermediate hash state using the SHA-1 transform 
 * constants and logical functions.
 */
void update_intermediate_hash_1(uint32_t hash[5], uint8_t buf[64]);

/**
 * update_intermediate_hash_256 - Process a single 512-bit SHA-256 message block.
 * @hash: The 256-bit internal state (8 x 32-bit words) to be updated.
 * @buf:  The 64-byte message block to be processed.
 *
 * Updates the current intermediate hash state using the SHA-256 transform 
 * constants and logical functions.
 */
void update_intermediate_hash_256(uint32_t hash[8], uint8_t buf[64]);

/**
 * update_intermediate_hash_512 - Process a single 1024-bit SHA-512 message block.
 * @hash: The 512-bit internal state (8 x 64-bit words) to be updated.
 * @buf:  The 128-byte message block to be processed.
 *
 * Updates the current intermediate hash state using the SHA-512 transform 
 * constants and logical functions.
 */
void update_intermediate_hash_512(uint64_t hash[8], uint8_t buf[128]);

#endif /* SHA_ALGO_H */