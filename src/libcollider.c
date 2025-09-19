#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/rand.h>
#include <math.h>
#include "collider.h"

static inline int intpow(int a, int n) { return (int)(pow(a, n) + 0.5); }

static void printHexArray(const uint8_t *hexArray, short len) {
    if (hexArray == NULL || len == 0) {
        fprintf(stderr, "printHexArray: hexArray == NULL or len == 0.\n");
        return;
    }

    for (int i = 0; i < len; i++) {
        printf("%02x ", hexArray[i]);
    }
}

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

// Traditional Birthday Attack where one takes out a smaller set of seed values and attempt to find collision.
// Uses a lot of disk space if you do not precompute the size.
// Setting warning=True will precompute roughly how much of disk space will be used, and ask you to confirm.
int birthdayAttack(Collider_CTX *ctx, unsigned long long updateFreq, bool warning) {
    FILE ** segFiles = NULL;
    unsigned long long nSegFiles = 0;
    if (ctx == NULL) {
        fprintf(stderr, "[-] cycleAttack: ctx not given.\n");
        return -1;
    }
    if (ctx->H == NULL) {
        fprintf(stderr, "[-] cycleAttack: ctx->H (hash function) not given.\n");
        return -1;
    }
    if (ctx->HashOutputLength == 0) {
        fprintf(stderr, "[-] cycleAttack: ctx->HashOutputLength cannot be zero.\n");
        return -1;
    }
    if (ctx->cycle.seed1 == NULL || ctx->cycle.s11 == NULL || ctx->cycle.seed2 == NULL || ctx->cycle.s21 == NULL || ctx->cycle.s12 == NULL || ctx->cycle.s22 == NULL) {
        fprintf(stderr, "[-] cycleAttack: ctx->seed* cannot be NULL.\n");
        return -1;
    }

    // If ctx->init == NULL, create random initial seed.
    if (ctx->init == NULL) {
        fprintf(stderr, "[-] cycleAttack: Initial seed cannot be NULL.\n");
        return -1;
    } 

    nSegFiles = (unsigned long long) intpow(256, ctx->birthday.segmentLength);

    // segmentLength = 1 -> segment file by the first byte
    // segmentLength = 2 -> segment file by the first two bytes.
    // segmentLength = i -> segment file by the first i bytes.
    segFiles = (FILE **) malloc(sizeof(FILE *) * nSegFiles);

}

// Constant Memory Attack via Floyd's Cycle Detection Algorithm and iterative application of the hash function.
// Based on amazing explanation by fgrieu at https://crypto.stackexchange.com/questions/115058/how-can-having-a-cycle-help-finding-a-hash-collision
// Returns 0 for successful attack
// Returns 1 for failed attack
// Returns -1 for miscellaneous error.
int cycleAttack(Collider_CTX *ctx, unsigned long long updateFreq) {
    while (true) {
        unsigned long long i = 0, l = 0;

        if (ctx == NULL) {
            fprintf(stderr, "[-] cycleAttack: ctx not given.\n");
            return -1;
        }
        if (ctx->H == NULL) {
            fprintf(stderr, "[-] cycleAttack: ctx->H (hash function) not given.\n");
            return -1;
        }
        if (ctx->HashOutputLength == 0) {
            fprintf(stderr, "[-] cycleAttack: ctx->HashOutputLength cannot be zero.\n");
            return -1;
        }
        if (ctx->cycle.seed1 == NULL || ctx->cycle.s11 == NULL || ctx->cycle.seed2 == NULL || ctx->cycle.s21 == NULL || ctx->cycle.s12 == NULL || ctx->cycle.s22 == NULL) {
            fprintf(stderr, "[-] cycleAttack: ctx->seed* cannot be NULL.\n");
            return -1;
        }

        // If ctx->init == NULL, create random initial seed.
        if (ctx->init == NULL) {
            fprintf(stderr, "[-] cycleAttack: Initial seed cannot be NULL.\n");
            return -1;
        } 

        if (ctx->cycle.randomizeInit) {
            int ret = generateRandomBytes(ctx->init, ctx->HashOutputLength);
            if (ret < 0) return -1;
        }

        if (updateFreq > 0) {
            printf("Initial seed: ");
            printHexArray(ctx->init, ctx->HashOutputLength);
            printf("\n");
        }

        memcpy(ctx->cycle.s11, ctx->init, ctx->HashOutputLength);
        memcpy(ctx->cycle.s21, ctx->init, ctx->HashOutputLength);

        // Floyd's cycle detection
        do {
            // t(cycle.seed1) -> H(t)
            // h(cycle.seed2) -> H^2(h)
            ctx->H(ctx->cycle.s11, ctx->cycle.seed1);
            memcpy(ctx->cycle.s11, ctx->cycle.seed1, ctx->HashOutputLength);

            ctx->H(ctx->cycle.s21, ctx->cycle.seed2);
            memcpy(ctx->cycle.s21, ctx->cycle.seed2, ctx->HashOutputLength);
            ctx->H(ctx->cycle.s21, ctx->cycle.seed2);
            memcpy(ctx->cycle.s21, ctx->cycle.seed2, ctx->HashOutputLength);

            i++;

            if (updateFreq > 0 && i % updateFreq == 0) {
                printf("Current Iteration: %llu\r", i);
            }
        } while (memcmp(ctx->cycle.seed1, ctx->cycle.seed2, ctx->HashOutputLength) != 0);
        if (updateFreq > 0) {
            printf("\n");
            printf("Found: H^%llu(s) = H^(2*%llu)(s)\n", i, i);
            printf("Computing cycle length...\n");
        }

        do {
            ctx->H(ctx->cycle.s11, ctx->cycle.seed1);
            memcpy(ctx->cycle.s11, ctx->cycle.seed1, ctx->HashOutputLength);
            l++;
            if (updateFreq > 0 && l % updateFreq == 0) {
                printf("Current Iteration: %llu\r", l);
            }
        } while (memcmp(ctx->cycle.seed1, ctx->cycle.seed2, ctx->HashOutputLength) != 0);
        if (updateFreq > 0) {
            printf("\nCycle length: %llu\n", l);
            printf("Resetting and repeating cycle length times to check for \"theoretical collision\".\n");
        }

        // Reset
        memcpy(ctx->cycle.seed1, ctx->init, ctx->HashOutputLength);
        memcpy(ctx->cycle.s11, ctx->init, ctx->HashOutputLength);
        memcpy(ctx->cycle.seed2, ctx->init, ctx->HashOutputLength);
        memcpy(ctx->cycle.s21, ctx->init, ctx->HashOutputLength);

        // Repeating cycle length times.
        for (i = 0; i < l; i++) {
            ctx->H(ctx->cycle.s21, ctx->cycle.seed2);
            memcpy(ctx->cycle.s21, ctx->cycle.seed2, ctx->HashOutputLength);
            if (updateFreq > 0 && i % updateFreq == 0) {
                printf("Progress: %llu / %llu (%.2lf%%)\r", i, l, (double) i / l * 100);
            }
        }
        if (updateFreq > 0) {
            printf("\n");
        }

        if (memcmp(ctx->init, ctx->cycle.seed2, ctx->HashOutputLength) == 0) {
            if (updateFreq > 0) {
                printf("Initial seed turned out to be part of a cycle... Starting over.\n");
            }
            continue;
        }

        // Theoretical collision detected! Finding actual seeds that caused them.
        if (updateFreq > 0) {
            printf("Theoretical collision detected! Finding actual seeds that caused them.\n");
        }

        i = 0;
        do {
            memcpy(ctx->cycle.s12, ctx->cycle.seed1, ctx->HashOutputLength);
            memcpy(ctx->cycle.s22, ctx->cycle.seed2, ctx->HashOutputLength);

            ctx->H(ctx->cycle.s11, ctx->cycle.seed1);
            memcpy(ctx->cycle.s11, ctx->cycle.seed1, ctx->HashOutputLength);
            ctx->H(ctx->cycle.s21, ctx->cycle.seed2);
            memcpy(ctx->cycle.s21, ctx->cycle.seed2, ctx->HashOutputLength);
            i++;

            if (updateFreq > 0 && i % updateFreq == 0) {
                printf("Current Iteration: %llu\r", i);
            }
        } while (memcmp(ctx->cycle.seed1, ctx->cycle.seed2, ctx->HashOutputLength) != 0);
        if (updateFreq > 0) {
            printf("\n");
            printf("Seed 1: ");
            printHexArray(ctx->cycle.s12, ctx->HashOutputLength);
            printf("\nSeed 2: ");
            printHexArray(ctx->cycle.s22, ctx->HashOutputLength);
            printf("\n");
        }

        memcpy(ctx->cycle.seed1, ctx->cycle.s12, ctx->HashOutputLength);
        memcpy(ctx->cycle.seed2, ctx->cycle.s22, ctx->HashOutputLength);

        if (updateFreq > 0) {
            printf("Checking for the last time if they give the same result.\n");
        }
        ctx->H(ctx->cycle.seed1, ctx->cycle.s11);
        ctx->H(ctx->cycle.seed2, ctx->cycle.s21);

        if (memcmp(ctx->cycle.s11, ctx->cycle.s21, ctx->HashOutputLength) == 0) {
            if (updateFreq > 0) {
                printf("Hash: ");
                printHexArray(ctx->cycle.s11, ctx->HashOutputLength);
                printf("\nHash Collision!!!\n");
            }
            return 0;
        } else {
            if (updateFreq > 0) {
                printf("False alarm :(\n");
            }
            return 1;
        }
    }
}