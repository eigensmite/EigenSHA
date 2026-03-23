#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "eigensha.h"

typedef struct {
    enum Sha sha;
    char *char_hash;
    char *text;
} test_pair;

#define TEST_PAIR(sha_type, hex_str, input_text) \
    (test_pair){                                 \
        .sha = (sha_type),                       \
        .char_hash = (hex_str),                  \
        .text = (input_text)                     \
    }

static const char *sha_to_string(enum Sha sha);

void run_test_pair(eigensha_ctx *ctx, const test_pair tp) {
    eigensha_init(ctx, tp.sha);
    eigensha_update(ctx, tp.text, strlen(tp.text));
    eigensha_finalize(ctx);
    uint8_t hash[128];
    eigensha_extract(hash, ctx);
    char char_hash[256];
    eigensha_hash_to_string(char_hash, hash, eigensha_get_hash_len(ctx));

    printf("%s\n", sha_to_string(tp.sha));
    printf("exp: %s\nget: %s\n", tp.char_hash, char_hash);
    assert(strncmp(char_hash, tp.char_hash, eigensha_get_hash_len(ctx)) == 0);
    printf("\u2714 - Success\n\n");





    eigensha_free(ctx);
}

int main(/* int argc, char **argv */) {
    eigensha_ctx ctx;

    run_test_pair(&ctx, TEST_PAIR(SHA_1,   "a9993e364706816aba3e25717850c26c9cd0d89d", "abc"));
    run_test_pair(&ctx, TEST_PAIR(SHA_224, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", "abc"));
    run_test_pair(&ctx, TEST_PAIR(SHA_256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc"));
    run_test_pair(&ctx, TEST_PAIR(SHA_384, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", "abc"));
    run_test_pair(&ctx, TEST_PAIR(SHA_512, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", "abc"));
    run_test_pair(&ctx, TEST_PAIR(SHA_512_224, "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa", "abc"));
    run_test_pair(&ctx, TEST_PAIR(SHA_512_256, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23", "abc"));

    run_test_pair(&ctx, TEST_PAIR(SHA_1,   "84983e441c3bd26ebaae4aa1f95129e5e54670f1", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
    run_test_pair(&ctx, TEST_PAIR(SHA_224, "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
    run_test_pair(&ctx, TEST_PAIR(SHA_256, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
    run_test_pair(&ctx, TEST_PAIR(SHA_384, "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
    run_test_pair(&ctx, TEST_PAIR(SHA_512, "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
    run_test_pair(&ctx, TEST_PAIR(SHA_512_224, "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
    run_test_pair(&ctx, TEST_PAIR(SHA_512_256, "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));

    run_test_pair(&ctx, TEST_PAIR(SHA_3_224, "e642824c3f8cf24ad09234ee7d3c766fc9a3a6168d0c944458a4523f", "abc"));
    run_test_pair(&ctx, TEST_PAIR(SHA_3_256, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", "abc"));
    run_test_pair(&ctx, TEST_PAIR(SHA_3_384, "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88c86d06951997c09c55447a363d5", "abc"));
    run_test_pair(&ctx, TEST_PAIR(SHA_3_512, "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0", "abc"));
        
    printf("All tests successful.\n");

    printf("\nCurrent testing done with simple NIST test vectors, not yet tested against full FIPS 180-4 and FIPS 202 vectors\n(https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing)\n");
    
}

static const char *sha_to_string(enum Sha sha) {
    switch (sha) {
        case SHA_1:       return "SHA-1:       ";
        case SHA_224:     return "SHA-224:     ";
        case SHA_256:     return "SHA-256:     ";
        case SHA_384:     return "SHA-384:     ";
        case SHA_512:     return "SHA-512:     ";
        case SHA_512_224: return "SHA-512/224: ";
        case SHA_512_256: return "SHA-512/256: ";
        case SHA_3_224:   return "SHA3-224:    ";
        case SHA_3_256:   return "SHA3-256:    ";
        case SHA_3_384:   return "SHA3-384:    ";
        case SHA_3_512:   return "SHA3-512:    ";
        default:          return "UNKNOWN?!?:  ";
    }
}