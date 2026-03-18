
#include "sha_ops.h"

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


