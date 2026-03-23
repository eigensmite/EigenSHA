
#include "eigensha.h"

void eigensha_init(eigensha_ctx *s, enum Sha sha) {
    switch (sha) {
        case SHA_1:       s->ops = &sha1_ops;       break;
        case SHA_224:     s->ops = &sha224_ops;     break;
        case SHA_256:     s->ops = &sha256_ops;     break;
        case SHA_384:     s->ops = &sha384_ops;     break;
        case SHA_512:     s->ops = &sha512_ops;     break;
        case SHA_512_224: s->ops = &sha512_224_ops; break;
        case SHA_512_256: s->ops = &sha512_256_ops; break;
        case SHA_3_224:   s->ops = &sha3_224_ops;   break;
        case SHA_3_256:   s->ops = &sha3_256_ops;   break;
        case SHA_3_384:   s->ops = &sha3_384_ops;   break;
        case SHA_3_512:   s->ops = &sha3_512_ops;   break;
        case SHA_COUNT: default: return;
    }
    s->ctx = malloc(s->ops->ctx_size);
    s->ops->init(s->ctx);
}

void eigensha_free(eigensha_ctx *s) {
    free(s->ctx);
}

void eigensha_update(eigensha_ctx *s, void *data, size_t len) {
    s->ops->update(s->ctx, data, len);
}

void eigensha_finalize(eigensha_ctx *s) {
    s->ops->finalize(s->ctx);
}

void eigensha_extract(uint8_t *hash, eigensha_ctx *s) {
    s->ops->extract(hash, s->ctx);
}

size_t eigensha_get_hash_len(eigensha_ctx *s) {
    return s->ops->hash_size;
}

void eigensha_hash_to_string(char *char_hash, uint8_t *hash, size_t hash_len) {
    for (size_t i = 0; i < hash_len; i++) {
        // (i * 2) because each byte takes up two characters in the string
        // %02x: 0 means pad with zeros, 2 means width of two, x means lowercase hex
        sprintf(char_hash + (i * 2), "%02x", hash[i]);
    }
    // Explicitly null-terminate the end of the string
    char_hash[hash_len * 2] = '\0';
}


// int main (int argc, char **argv) {

//     uint8_t buffer[4096];
//     size_t bytesRead;
//     // printf("stdin?\n");
//     // while ((
//         bytesRead = fread(buffer, 1, sizeof(buffer), stdin);
//     // ) > 0) {
//     //     // printf("bytesRead %ld\n", bytesRead);
//     // }

//     for (int i = 0; i < SHA_COUNT; i++) {
//         sha_ctx ctx;

//         sha_ctx_init(&ctx, i);

//         sha_update(&ctx, buffer, bytesRead);

//         sha_finalize(&ctx);

//         uint8_t hash[128] = {0};
//         sha_extract(hash, &ctx);

//         printf("%s", sha_to_string(i));

//         for (int i = 0; i < ctx.ops->hash_size; i++) printf("%02x", hash[i]);
//         printf("\n");

//         sha_ctx_free(&ctx);
//     }

//     return 0;

// }