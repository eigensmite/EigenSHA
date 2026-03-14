
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "keccak_f.h"
#include "sha3.h"


static void parameters(int* index, int* length, char *filename, int argc, char** argv) {
    if (argc > *index) {

        if (strcmp(argv[*index], "-h") == 0 || strcmp(argv[*index], "--help") == 0) {
            fprintf(stderr, "Usage: \n\t%s <../path/to/file.txt> [-224|-254|-384|-512]\n\tcat <../path/to/file.txt> | %s [-224|-254|-384|-512]\n", argv[0], argv[0]);
            exit(1);
        } else if (strcmp(argv[*index], "-256") == 0) {
            *length = 256;
        } else if (strcmp(argv[*index], "-224") == 0) {
            *length = 224;
        } else if (strcmp(argv[*index], "-384") == 0) {
            *length = 384;
        } else if (strcmp(argv[*index], "-512") == 0) {
            *length = 512;
        } else {
            strncpy(filename, argv[*index], 255);
        }
    }
}


int main (int argc, char **argv) {

    int bits = 256;
    char filename[256] = {0};

    for (int i = 1; i < 3; i++){
        parameters(&i, &bits, filename, argc, argv);
    }

    sponge_ctx ctx;
    switch (bits) {
        case 224: sponge_init(&ctx, SHA3_224); break;
        case 256: sponge_init(&ctx, SHA3_256); break;
        case 384: sponge_init(&ctx, SHA3_384); break;
        case 512: sponge_init(&ctx, SHA3_512); break;
        default: exit(1);
    }

    uint8_t buffer[4096];
    size_t bytesRead;

    FILE *f;
    if (filename[0] == 0) { f = stdin; }
    else {
        f = fopen(filename, "rb");
    }

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), f)) > 0)
        sponge_absorb(&ctx, buffer, bytesRead);

    sponge_pad(&ctx);

    uint8_t hash[512];
    sponge_squeeze(hash, &ctx);

    for (int i = 0; i < ctx.out; i++) printf("%02x", hash[i]);
    if (filename[0] != 0) printf("  %s\n", filename);
    else printf("  -\n");
    return 0;
}