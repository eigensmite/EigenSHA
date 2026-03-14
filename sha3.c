
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmp.h>
#include <math.h>
#include <string.h>
#include <assert.h>

typedef struct SHA_3 {
    size_t r;
    size_t d;
} SHA_3;

void print_lanes(uint64_t A[5][5]) {
    printf("Xor'd state (as lanes of integers)\n");
    for (int y = 0; y < 5; y++) {
        for(int x = 0; x < 5; x++) {
            printf("\t[%d, %d] = %016lX\n", y, x, A[y][x]);
        }
    }
}

void print_state(uint64_t A[5][5]) {
    printf("\t");
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            for (int z = 0; z < 64; z+=8) {
                printf("%02lX ", (A[y][x] >> z) & 0xff);
            }
            if ((y+x) % 2 == 1) printf("\n\t");
        }
    }
    printf("\n\n");
}


typedef size_t(*pad_fn)(mpz_t, const mpz_t, const size_t);
typedef void(*perm_fn)(mpz_t, const mpz_t);

const static int OFFSET_TABLE[5][5] = {
    {  0,  1, 62, 28, 27 },
    { 36, 44,  6, 55, 20 },
    {  3, 10, 43, 25, 39 },
    { 41, 45, 15, 21,  8 },
    { 18,  2, 61, 56, 14 }
};

const static uint64_t RC[24] = { 
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

static inline void _theta(uint64_t A[5][5]) {
    uint64_t C[5] = {0};
    for (int x = 0; x < 5; x++) C[x] = A[0][x] ^ A[1][x] ^ A[2][x] ^ A[3][x] ^ A[4][x];
    for (int y = 0; y < 5; y++) for (int x = 0; x < 5; x++)
        A[y][x] ^= C[(x+4)%5] ^ ((C[(x+1)%5] >> 63) | (C[(x+1)%5] << 1));
}

static inline void _rho(uint64_t A[5][5]) {
    for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++) 
        A[y][x] = (A[y][x] << OFFSET_TABLE[y][x]) | (A[y][x] >> (64 - OFFSET_TABLE[y][x]));     
}

static inline void _pi(uint64_t A[5][5]) {
    uint64_t prev = A[0][1], temp;
    int prev_x = 1, prev_y = 0;
    for (int t = 0; t < 24; t++) {
        int x = prev_y, y = (2 * prev_x + 3 * prev_y) % 5;
        temp = A[y][x], A[y][x] = prev, prev = temp;
        prev_x = x, prev_y = y;
    }
}

static inline void _chi(uint64_t A[5][5]) {
    uint64_t R[5];
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) R[x] = A[y][x];
        for (int x = 0; x < 5; x++) A[y][x] = R[x] ^ ((~R[(x+1)%5]) & R[(x+2)%5]);
    }
}


static inline void _iota(uint64_t A[5][5], const int i) {
    A[0][0] ^= RC[i];
}

static inline void keccak_f(uint64_t state[25]) {
    uint64_t (*A)[5] = (uint64_t (*)[5])state;
    for(int i = 0; i < 24; i++) {
        _theta(A);        // 𝜃
          _rho(A);       // 𝜌
           _pi(A);      // 𝜋
          _chi(A);     // 𝜒
        _iota(A, i);  // 𝜄
    }
}

// r is always in bits
static void sponge_absorb_bytes(uint64_t state[25], uint8_t buffer[4096], size_t *preloaded_bytes, const size_t buffer_len, const struct SHA_3 sha){
    const size_t r = sha.r;

    uint8_t *buffer_start = buffer;

    size_t bytes_remain = buffer_len - (buffer - buffer_start);

    while (bytes_remain + *preloaded_bytes >= r/8) {
        #pragma region start
        #pragma endregion
        
        int i;
        // for (i = *preloaded_bytes; i < r/8 && i % 8 == 0; i+=8) {
        //     state[*preloaded_bytes/8] ^= ((uint64_t *)buffer)[0];
        //     buffer += 8;
        // } 
        // *preloaded_bytes += i;

        for (i = *preloaded_bytes; i < r/8; i++) {
            state[i/8] ^= ((uint64_t) buffer[0]) << (8*(i%8));
            buffer++;
        }

        keccak_f(state);
        *preloaded_bytes = 0;

        bytes_remain = buffer_len - (buffer - buffer_start);
    }

    for (int i = *preloaded_bytes; i < bytes_remain; i++) {
        state[i/8] ^= ((uint64_t) buffer[0]) << (8*(i%8));
        buffer++;
    } 
    *preloaded_bytes = (bytes_remain + *preloaded_bytes) % (r/8);
}


static void sponge_squeeze_hash(uint8_t *hash, uint64_t state[25], size_t *preloaded_bytes, const struct SHA_3 sha) {
    const size_t r = sha.r, d = sha.d;

    size_t len_pad = ((r - (4 + 8*(*preloaded_bytes)) % r) % r + 4)/8;
    state[(*preloaded_bytes)/8] ^= ((uint64_t) 0x06) << (8*((*preloaded_bytes)%8));
    state[((*preloaded_bytes)+len_pad-1)/8] ^= ((uint64_t) 0x80) << (8*(((*preloaded_bytes)+len_pad-1)%8));
    keccak_f(state);
    *preloaded_bytes = 0;

    memcpy(hash, state, sha.d/8);

}


static void parameters(int* index, int* length, char *filename, int argc, char** argv) {
    if (argc > *index) {
        if (strcmp(argv[*index], "-256") == 0) {
            *length = 256;
        } else if (strcmp(argv[*index], "-224") == 0) {
            *length = 224;
        } else if (strcmp(argv[*index], "-384") == 0) {
            *length = 384;
        } else if (strcmp(argv[*index], "-512") == 0) {
            *length = 512;
        } else {
            strncpy(filename, argv[*index], 255);
            // fprintf(stderr, "Usage: %s [-224|-254|-384|-512] -a\n", argv[0]);
            // exit(1);
        }
    }
}

const struct SHA_3 SHA3_224 = {.r=1152,.d=224};
const struct SHA_3 SHA3_256 = {.r=1088,.d=256};
const struct SHA_3 SHA3_384 = {.r=832, .d=384};
const struct SHA_3 SHA3_512 = {.r=576, .d=512};

int main (int argc, char **argv) {

    int bits = 256;
    char filename[256] = {0};

    for (int i = 1; i < 3; i++){
        parameters(&i, &bits, filename, argc, argv);
    }

    struct SHA_3 sha;
    switch (bits) {
        case 224: sha = SHA3_224; break;
        case 256: sha = SHA3_256; break;
        case 384: sha = SHA3_384; break;
        case 512: sha = SHA3_512; break;
        default: exit(1);
    }


    uint8_t buffer[4096];
    size_t bytesRead;

    FILE *f;
    if (filename[0] == 0) { f = stdin; }
    else {
        f = fopen(filename, "rb");
    }

    uint64_t state[25] = {0};
    size_t preloaded_bytes = 0;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), f)) > 0) {

        sponge_absorb_bytes(state, buffer, &preloaded_bytes, bytesRead, sha);

    }
    //printf("preloaded %ld\n", preloaded_bytes);
    //sponge_absorb_bytes(state, buffer, &preloaded_bytes, 0, r, 1);

    uint8_t hash[512];
    sponge_squeeze_hash(hash, state, &preloaded_bytes, sha);

    for (int i = 0; i < sha.d/8; i++) printf("%02x", hash[i]);
    printf("\n");
    //exit(1);
    
}