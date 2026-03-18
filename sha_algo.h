
#ifndef SHA_ALGO_H
#define SHA_ALGO_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void update_intermediate_hash_1(uint32_t hash[5], uint8_t buf[64]);

void update_intermediate_hash_256(uint32_t hash[5], uint8_t buf[64]);

void update_intermediate_hash_512(uint64_t hash[5], uint8_t buf[64]);


#endif
