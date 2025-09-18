#include <stdio.h>
#include <stdbool.h>
#include <openssl/rand.h>
#include "collider.h"

static int generateRandomBytes(uint8_t *buffer, short len) {
    if (buffer == NULL || len == 0) {
        fprintf(stderr, "generateRandomBytes: either buffer == NULL or len == 0\n");
        return -1;
    }

    if (RAND_bytes(buffer, len) != 1) {
        fprintf(stderr, "generateRandomBytes: OpenSSL RAND_bytes failed.\n");
        return -1;
    }

    return 0;
}

// Constant Memory Attack via Floyd's Cycle Detection Algorithm and iterative application of the hash function.
void cycleAttack(Collider_CTX *ctx, unsigned long long updateFreq, bool retry) {
    if (ctx == NULL) {
        fprintf(stderr, "[-] cycleAttack: ctx not given.\n");
        return;
    }
    if (ctx->H == NULL) {
        fprintf(stderr, "[-] cycleAttack: ctx->H (hash function) not given.\n");
        return;
    }
    if (ctx->HashOutputLength == 0) {
        fprintf(stderr, "[-] cycleAttack: ctx->HashOutputLength cannot be zero.\n");
        return;
    }
    if (ctx->seed1 == NULL || ctx->seed1Buffer == NULL || ctx->seed2 == NULL || ctx->seed2Buffer == NULL) {
        fprintf(stderr, "[-] cycleAttack: ctx->seed* cannot be NULL.\n");
        return;
    }

    // If ctx->init == NULL, create random initial seed.
    if (ctx->init == NULL) {
        int ret = generateRandomBytes(ctx->init, ctx->HashOutputLength);
        if (ret < 0) return;
    }

}