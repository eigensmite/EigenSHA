
#include "sha2.h"

// #define DEBUG


void print_hash_1(const uint32_t hash[5]) {
    for (int i = 0; i < 5; i++) {
        printf("H[%d] = %08X\n", i, hash[i]);
    }
    printf("\n");
}

void print_block_1(const uint32_t block[16]) {
    for(int i = 0; i < 16; i++) {
        printf("W[%d] = %08X\n", i, block[i]);
    }
    printf("\n");
}

void print_hash(const uint32_t hash[8]) {
    for (int i = 0; i < 8; i++) {
        printf("H[%d] = %08X\n", i, hash[i]);
    }
    printf("\n");
}

void print_block(const uint32_t block[16]) {
    for(int i = 0; i < 16; i++) {
        printf("W[%d] = %08X\n", i, block[i]);
    }
    printf("\n");
}

void print_hash_512(const uint64_t hash[8]) {
    for (int i = 0; i < 8; i++) {
        printf("H[%d] = %016lX\n", i, hash[i]);
    }
    printf("\n");
}

void print_block_512(const uint64_t block[16]) {
    for(int i = 0; i < 16; i++) {
        printf("W[%d] = %016lX\n", i, block[i]);
    }
    printf("\n");
}

/** SHA-224 and SHA-256 functions **/
static inline uint32_t Ch_32(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t Maj_32(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t f_32(uint32_t x, uint32_t y, uint32_t z, size_t t) {
    if (t < 20) return Ch_32(x,y,z);
    if (t < 40) return x ^ y ^ z;
    if (t < 60) return Maj_32(x,y,z);
    return x ^ y ^ z;
}

static inline uint32_t ROTR_32(uint32_t x, size_t n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t ROTL_32(uint32_t x, size_t n) {
    return (x << n) | (x >> (32 - n));
}

static inline uint32_t SHR_32(uint32_t x, size_t n) {
    return x >> n;
}

static inline uint32_t BIG_SIGMA_256_0(uint32_t x) {
    return ROTR_32(x, 2) ^ ROTR_32(x, 13) ^ ROTR_32(x, 22);
}

static inline uint32_t BIG_SIGMA_256_1(uint32_t x) {
    return ROTR_32(x, 6) ^ ROTR_32(x, 11) ^ ROTR_32(x, 25);
}

static inline uint32_t LITTLE_SIGMA_256_0(uint32_t x) {
    return ROTR_32(x, 7) ^ ROTR_32(x, 18) ^ SHR_32(x, 3);
}

static inline uint32_t LITTLE_SIGMA_256_1(uint32_t x) {
    return ROTR_32(x, 17) ^ ROTR_32(x, 19) ^ SHR_32(x, 10);
}

/** SHA-384 and SHA-512 functions **/
static inline uint64_t Ch_64(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint64_t Maj_64(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint64_t ROTR_64(uint64_t x, size_t n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t SHR_64(uint64_t x, size_t n) {
    return x >> n;
}

static inline uint64_t BIG_SIGMA_512_0(uint64_t x) {
    return ROTR_64(x, 28) ^ ROTR_64(x, 34) ^ ROTR_64(x, 39);
}

static inline uint64_t BIG_SIGMA_512_1(uint64_t x) {
    return ROTR_64(x, 14) ^ ROTR_64(x, 18) ^ ROTR_64(x, 41);
}

static inline uint64_t LITTLE_SIGMA_512_0(uint64_t x) {
    return ROTR_64(x, 1) ^ ROTR_64(x, 8) ^ SHR_64(x, 7);
}

static inline uint64_t LITTLE_SIGMA_512_1(uint64_t x) {
    return ROTR_64(x, 19) ^ ROTR_64(x, 61) ^ SHR_64(x, 6);
}


static const uint32_t K_1[4] = {
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
};

static const uint32_t K_256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint64_t K_512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static const uint32_t H_0_1[5] = { 
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 
};

static const uint32_t H_0_224[8] = { 
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};

static const uint32_t H_0_256[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint64_t H_0_384[8] = {
    0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
    0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
    0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
};

static const uint64_t H_0_512[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint64_t H_0_512_224[8] = {
    0x8C3D37C819544DA2ULL, 0x73E1996689DCD4D6ULL,
    0x1DFAB7AE32FF9C82ULL, 0x679DD514582F9FCFULL,
    0x0F6D2B697BD44DA8ULL, 0x77E36F7304C48942ULL,
    0x3F9D85A86A1D36C8ULL, 0x1112E6AD91D692A1ULL
};

static const uint64_t H_0_512_256[8] = {
    0x22312194FC2BF72CULL, 0x9F555FA3C84C64C2ULL,
    0x2393B86B6F53B151ULL, 0x963877195940EABDULL,
    0x96283EE2A88EFFE3ULL, 0xBE5E1E2553863992ULL,
    0x2B0199FC2C85B8AAULL, 0x0EB72DDC81C52CA2ULL
};

static void update_intermediate_hash_1(sha1_ctx *ctx) {
    uint32_t W[80];
    
    uint32_t (*M) = (uint32_t *)ctx->buf;
    for (int t = 0; t < 16; t++) {
        W[t] = __builtin_bswap32(M[t]);
    }
    for (int t = 16; t < 80; t++) {
        W[t] = ROTL_32(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
    }

    #if defined(DEBUG)
    print_hash_1(ctx->hash);
    print_block_1(W);
    #endif

    uint32_t    a = ctx->hash[0], b = ctx->hash[1],
                c = ctx->hash[2], d = ctx->hash[3],
                e = ctx->hash[4];
                
        #if defined(DEBUG)
        printf("          A        B        C        D        E\n");
        #endif

    for (int t = 0; t < 80; t++) {
        uint32_t T = ROTL_32(a, 5) + f_32(b,c,d,t) + e + K_1[t/20] + W[t];
        e = d; d = c; c = ROTL_32(b, 30); b = a; a = T;

        #if defined(DEBUG)
        printf("t=%2d: %08X %08X %08X %08X %08X\n",t,a,b,c,d,e);
        #endif
    }
    ctx->hash[0] += a; ctx->hash[1] += b; ctx->hash[2] += c;
    ctx->hash[3] += d; ctx->hash[4] += e;
}

static void update_intermediate_hash_512(sha512_ctx *ctx) {
    uint64_t W[80];

    /* build message schedule */
    uint64_t (*M) = (uint64_t *)ctx->buf;
    for (int t = 0; t < 16; t++) {
        W[t] = __builtin_bswap64(M[t]);
    }
    for (int t = 16; t < 80; t++) {
        W[t] = LITTLE_SIGMA_512_1(W[t-2]) + W[t-7] + 
                LITTLE_SIGMA_512_0(W[t-15]) + W[t-16];
    }

    #if defined(DEBUG)
    print_hash_512(ctx->hash);
    print_block_512(W);
    #endif

    uint64_t    a = ctx->hash[0], b = ctx->hash[1],
                c = ctx->hash[2], d = ctx->hash[3],
                e = ctx->hash[4], f = ctx->hash[5],
                g = ctx->hash[6], h = ctx->hash[7];

    #if defined(DEBUG)
    printf("                  A                B                C                D                E                F                G                H\n");
    #endif

        for (int t = 0; t < 80; t++) {
        uint64_t T_1 = h + BIG_SIGMA_512_1(e) + 
            Ch_64(e, f, g) + K_512[t] + W[t];
        uint64_t T_2 = BIG_SIGMA_512_0(a) + Maj_64(a,b,c);
        h = g; g = f; f = e; e = d + T_1; 
        d = c; c = b; b = a; a = T_1 + T_2;

        #if defined(DEBUG)
        printf("t=%2d: %016lX %016lX %016lX %016lX %016lX %016lX %016lX %016lX\n",t,a,b,c,d,e,f,g,h);
        #endif
    }

    ctx->hash[0] += a; ctx->hash[1] += b;
    ctx->hash[2] += c; ctx->hash[3] += d;
    ctx->hash[4] += e; ctx->hash[5] += f;
    ctx->hash[6] += g; ctx->hash[7] += h;
}

static void update_intermediate_hash_256(sha256_ctx *ctx) {
    uint32_t W[64];
    /* build message schedule */
    uint32_t (*M) = (uint32_t *)ctx->buf;
    for (int t = 0; t < 16; t++) {
        W[t] = __builtin_bswap32(M[t]);
    }
    for (int t = 16; t < 64; t++) {
        W[t] = LITTLE_SIGMA_256_1(W[t-2]) + W[t-7] + 
                LITTLE_SIGMA_256_0(W[t-15]) + W[t-16];
    }

    #if defined(DEBUG)
    print_hash(ctx->hash);
    print_block(W);
    #endif

    uint32_t    a = ctx->hash[0], b = ctx->hash[1],
                c = ctx->hash[2], d = ctx->hash[3],
                e = ctx->hash[4], f = ctx->hash[5],
                g = ctx->hash[6], h = ctx->hash[7];
        
        #if defined(DEBUG)
        printf("          A        B        C        D        E        F        G        H\n");
        #endif

    for (int t = 0; t < 64; t++) {
        uint32_t T_1 = h + BIG_SIGMA_256_1(e) + 
            Ch_32(e, f, g) + K_256[t] + W[t];
        uint32_t T_2 = BIG_SIGMA_256_0(a) + Maj_32(a,b,c);
        h = g; g = f; f = e; e = d + T_1; 
        d = c; c = b; b = a; a = T_1 + T_2;
        #if defined(DEBUG)
        printf("t=%2d: %08X %08X %08X %08X %08X %08X %08X %08X\n",t,a,b,c,d,e,f,g,h);
        #endif
    }

    ctx->hash[0] += a; ctx->hash[1] += b;
    ctx->hash[2] += c; ctx->hash[3] += d;
    ctx->hash[4] += e; ctx->hash[5] += f;
    ctx->hash[6] += g; ctx->hash[7] += h;
}

void sha1_update(sha1_ctx *ctx, uint8_t *data, size_t len) {

    // printf("\nupdate\n");
    while (len > 0) {
        size_t take = 512/8 - ctx->pos;
        if (take > len) take = len;
        memcpy(ctx->buf + ctx->pos, data, take);
        data += take;
        ctx->pos += take;
        // printf("take: %ld\n", take);
        // printf("pos:%ld",ctx->pos);
        ctx->len += take;
        len -= take;
        if (ctx->pos == 512/8) {
            update_intermediate_hash_1(ctx);
            ctx->pos = 0;
        }
    }
}

void sha512_update(sha512_ctx *ctx, uint8_t *data, size_t len) {
    while (len > 0 ) {
        size_t take = 1024/8 - ctx->pos;
        if (take > len) take = len;
        memcpy(ctx->buf + ctx->pos, data, take);
        data += take;
        ctx->pos += take;
        ctx->len += take;
        len -= take;
        if (ctx->pos == 1024/8) {
            update_intermediate_hash_512(ctx);
            ctx->pos = 0;
        }
    }
}

void sha384_update(sha384_ctx *ctx, uint8_t *data, size_t len) {
    sha512_update((sha512_ctx *)ctx, data, len);
}

void sha512_256_update(sha512_256_ctx *ctx, uint8_t *data, size_t len) {
    sha512_update((sha512_ctx *)ctx, data, len);
}

void sha512_224_update(sha512_224_ctx *ctx, uint8_t *data, size_t len) {
    sha512_update((sha512_ctx *)ctx, data, len);
}


void sha256_update(sha256_ctx *ctx, uint8_t *data, size_t len) {
    while (len > 0) {
        size_t take = 512/8 - ctx->pos;
        if (take > len) take = len;
        //printf("copy\n");
        memcpy(ctx->buf + ctx->pos, data, take);
        data += take;
        ctx->pos += take;
        ctx->len += take;
        len -= take;
        if (ctx->pos == 512/8) {
            update_intermediate_hash_256(ctx);
            ctx->pos = 0;
        }
    }
}

void sha224_update(sha224_ctx *ctx, uint8_t *data, size_t len) {
    sha256_update((sha256_ctx *)ctx, data, len);
}

void sha1_init(sha1_ctx *ctx) {
    for (int i = 0; i < 5; i++) {
        ctx->hash[i] = H_0_1[i];
    }
    ctx->pos = 0;
    ctx->len = 0;
    ctx->out = 20;
}

void sha512_init(sha512_ctx *ctx) {
    for (int i = 0; i < 8; i++) {
        ctx->hash[i] = H_0_512[i];
    }
    ctx->pos = 0;
    ctx->len = 0;
    ctx->out = 64;
}

void sha384_init(sha384_ctx *ctx) {
    for (int i = 0; i < 8; i++) {
        ctx->hash[i] = H_0_384[i];
    }
    ctx->pos = 0;
    ctx->len = 0;
    ctx->out = 48;
}

void sha512_256_init(sha512_256_ctx *ctx) {
    for (int i = 0; i < 8; i++) {
        ctx->hash[i] = H_0_512_256[i];
    }
    ctx->pos = 0;
    ctx->len = 0;
    ctx->out = 32;
}

void sha512_224_init(sha512_224_ctx *ctx) {
    for (int i = 0; i < 8; i++) {
        ctx->hash[i] = H_0_512_224[i];
    }
    ctx->pos = 0;
    ctx->len = 0;
    ctx->out = 28;
}

void sha256_init(sha256_ctx *ctx) {
    for (int i = 0; i < 8; i++) {
        ctx->hash[i] = H_0_256[i];
    }
    ctx->pos = 0;
    ctx->len = 0;
    ctx->out = 32;
}

void sha224_init(sha224_ctx *ctx) {
    for (int i = 0; i < 8; i++) {
        ctx->hash[i] = H_0_224[i];
    }
    ctx->pos = 0;
    ctx->len = 0;
    ctx->out = 28;
}

void sha1_finalize(sha1_ctx *ctx) {
    int zero_bits = 448 - (8*ctx->len % 512) - 1;
    if (zero_bits < 0) {
        memset(ctx->buf + ctx->pos, 0x00, 512/8 - ctx->pos);
        ctx->buf[ctx->pos] = 0x80;
        update_intermediate_hash_1(ctx);
        ctx->pos = 0;
        // printf("hi\n");
    }    
    memset(ctx->buf + ctx->pos, 0x00, 512/8 - ctx->pos);
    // printf("\n%s pos:%ld\n\n",ctx->buf,ctx->pos);
    if (zero_bits >= 0) ctx->buf[ctx->pos] = 0x80;
    ((uint64_t *)ctx->buf)[7] = __builtin_bswap64(ctx->len*8ULL);
    update_intermediate_hash_1(ctx);
    ctx->pos = 0;
}

void sha512_finalize(sha512_ctx *ctx) {
    int zero_bits = 896 - (8*ctx->len % 1024) - 1;
    if (zero_bits < 0) {
        memset(ctx->buf + ctx->pos, 0x00, 1024/8 - ctx->pos);
        ctx->buf[ctx->pos] = 0x80;
        update_intermediate_hash_512(ctx);
        ctx->pos = 0;
    }
    memset(ctx->buf + ctx->pos, 0x00, 1024/8 - ctx->pos);
    if (zero_bits >= 0) ctx->buf[ctx->pos] = 0x80;
    ((__uint128_t *)ctx->buf)[7] = __builtin_bswap128(ctx->len*8ULL);
    update_intermediate_hash_512(ctx);
    ctx->pos = 0;
}

void sha384_finalize(sha384_ctx *ctx) {
    sha512_finalize((sha512_ctx *)ctx);
}

void sha512_256_finalize(sha512_256_ctx *ctx) {
    sha512_finalize((sha512_ctx *)ctx);
}

void sha512_224_finalize(sha512_224_ctx *ctx) {
    sha512_finalize((sha512_ctx *)ctx);
}

void sha256_finalize(sha256_ctx *ctx) {
    int zero_bits = 448 - (8*ctx->len % 512) - 1;
    // printf("zero bits %d\n", zero_bits);
    if (zero_bits < 0) {
        memset(ctx->buf + ctx->pos, 0x00, 512/8 - ctx->pos);
        ctx->buf[ctx->pos] = 0x80;
        update_intermediate_hash_256(ctx);
        ctx->pos = 0;
    }    
    memset(ctx->buf + ctx->pos, 0x00, 512/8 - ctx->pos);
    if (zero_bits >= 0) ctx->buf[ctx->pos] = 0x80;
    ((uint64_t *)ctx->buf)[7] = __builtin_bswap64(ctx->len*8ULL);
    update_intermediate_hash_256(ctx);
    ctx->pos = 0;
}

void sha224_finalize(sha224_ctx *ctx) {
    sha256_finalize((sha256_ctx *)ctx);
}

void sha1_extract(uint8_t hash[20], sha1_ctx *ctx) {
    for (int i = 0; i < 5; i++)
        ((uint32_t *)hash)[i] = __builtin_bswap32(ctx->hash[i]);
}


void sha512_extract(uint8_t hash[64], sha512_ctx *ctx) {
    for (int i = 0; i < 8; i++)
        ((uint64_t *)hash)[i] = __builtin_bswap64(ctx->hash[i]);
}

void sha384_extract(uint8_t hash[48], sha384_ctx *ctx) {
    for (int i = 0; i < 6; i++)
        ((uint64_t *)hash)[i] = __builtin_bswap64(ctx->hash[i]);
}

void sha512_256_extract(uint8_t hash[32], sha512_256_ctx *ctx) {
    for (int i = 0; i < 4; i++)
        ((uint64_t *)hash)[i] = __builtin_bswap64(ctx->hash[i]);
}

void sha512_224_extract(uint8_t hash[28], sha512_224_ctx *ctx) {
    for (int i = 0; i < 3; i++)
        ((uint64_t *)hash)[i] = __builtin_bswap64(ctx->hash[i]);
    ((uint32_t *)hash)[6] = __builtin_bswap64(ctx->hash[3]);
}

void sha256_extract(uint8_t hash[32], sha256_ctx *ctx) {
    for(int i = 0; i < 8; i++)
        ((uint32_t *)hash)[i] = __builtin_bswap32(ctx->hash[i]);
}

void sha224_extract(uint8_t hash[28], sha224_ctx *ctx) {
    for(int i = 0; i < 7; i++)
        ((uint32_t *)hash)[i] = __builtin_bswap32(ctx->hash[i]);
}

DEFINE_SHA_WRAPPERS(sha1,       sha1_ctx)
DEFINE_SHA_WRAPPERS(sha224,     sha224_ctx)
DEFINE_SHA_WRAPPERS(sha256,     sha256_ctx)
DEFINE_SHA_WRAPPERS(sha384,     sha384_ctx)
DEFINE_SHA_WRAPPERS(sha512,     sha512_ctx)
DEFINE_SHA_WRAPPERS(sha512_224, sha512_224_ctx)
DEFINE_SHA_WRAPPERS(sha512_256, sha512_256_ctx)

DEFINE_SHA_3_WRAPPERS(sha3_224, SHA3_224)
DEFINE_SHA_3_WRAPPERS(sha3_256, SHA3_256)
DEFINE_SHA_3_WRAPPERS(sha3_384, SHA3_384)
DEFINE_SHA_3_WRAPPERS(sha3_512, SHA3_512)


const sha_ops sha1_ops       = DEFINE_SHA_OPS(sha1,       sha1_ctx,       20);
const sha_ops sha224_ops     = DEFINE_SHA_OPS(sha224,     sha224_ctx,     28);
const sha_ops sha256_ops     = DEFINE_SHA_OPS(sha256,     sha256_ctx,     32);
const sha_ops sha384_ops     = DEFINE_SHA_OPS(sha384,     sha384_ctx,     48);
const sha_ops sha512_ops     = DEFINE_SHA_OPS(sha512,     sha512_ctx,     64);
const sha_ops sha512_224_ops = DEFINE_SHA_OPS(sha512_224, sha512_224_ctx, 28);
const sha_ops sha512_256_ops = DEFINE_SHA_OPS(sha512_256, sha512_256_ctx, 32);

const sha_ops sha3_224_ops = DEFINE_SHA_3_OPS(sha3_224, 28);
const sha_ops sha3_256_ops = DEFINE_SHA_3_OPS(sha3_256, 32);
const sha_ops sha3_384_ops = DEFINE_SHA_3_OPS(sha3_384, 48);
const sha_ops sha3_512_ops = DEFINE_SHA_3_OPS(sha3_512, 64);


typedef struct {
    const sha_ops *ops;
    void *ctx;
} sha_ctx;

static inline void sha_ctx_init(sha_ctx *s, enum Sha sha) {
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
    }
    s->ctx = malloc(s->ops->ctx_size);
    s->ops->init(s->ctx);
}

static inline void sha_ctx_free(sha_ctx *s) {
    free(s->ctx);
}

static inline void sha_ctx_update(sha_ctx *s, void *data, size_t len) {
    s->ops->update(s->ctx, data, len);
}

static inline void sha_ctx_finalize(sha_ctx *s) {
    s->ops->finalize(s->ctx);
}

static inline void sha_ctx_extract(uint8_t *hash, sha_ctx *s) {
    s->ops->extract(hash, s->ctx);
}


const char *sha_to_string(enum Sha sha) {
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

int main (int argc, char **argv) {

    uint8_t buffer[4096];
    size_t bytesRead;
    // printf("stdin?\n");
    // while ((
        bytesRead = fread(buffer, 1, sizeof(buffer), stdin);
    // ) > 0) {
    //     // printf("bytesRead %ld\n", bytesRead);
    // }

    for (int i = 0; i < SHA_COUNT; i++) {
        sha_ctx ctx;

        sha_ctx_init(&ctx, i);

        sha_update(&ctx, buffer, bytesRead);

        sha_finalize(&ctx);

        uint8_t hash[128] = {0};
        sha_extract(hash, &ctx);

        printf("%s", sha_to_string(i));

        for (int i = 0; i < ctx.ops->hash_size; i++) printf("%02x", hash[i]);
        printf("\n");

        sha_ctx_free(&ctx);
    }

    return 0;

}