#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/rand.h>
#include "collider.h"

void printHexArray(const uint8_t *hexArray, short len) {
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

// Constant Memory Attack via Floyd's Cycle Detection Algorithm and iterative application of the hash function.
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
        if (ctx->seed1 == NULL || ctx->s11 == NULL || ctx->seed2 == NULL || ctx->s21 == NULL || ctx->s12 == NULL || ctx->s22 == NULL) {
            fprintf(stderr, "[-] cycleAttack: ctx->seed* cannot be NULL.\n");
            return -1;
        }

        // If ctx->init == NULL, create random initial seed.
        if (ctx->init == NULL) {
            int ret = generateRandomBytes(ctx->init, ctx->HashOutputLength);
            if (ret < 0) return -1;
        }
        if (updateFreq > 0) {
            printf("Initial seed: ");
            printHexArray(ctx->init, ctx->HashOutputLength);
            printf("\n");
        }

        // Floyd's cycle detection
        do {
            // t(seed1) -> H(t)
            // h(seed2) -> H^2(h)
            ctx->H(ctx->s11, ctx->seed1);
            memcpy(ctx->s11, ctx->seed1, ctx->HashOutputLength);

            ctx->H(ctx->s21, ctx->seed2);
            memcpy(ctx->s21, ctx->seed2, ctx->HashOutputLength);
            ctx->H(ctx->s21, ctx->seed2);
            memcpy(ctx->s21, ctx->seed2, ctx->HashOutputLength);

            i++;

            if (updateFreq > 0 && i % updateFreq == 0) {
                printf("Current Iteration: %llu\r", i);
            }
        } while (memcmp(ctx->seed1, ctx->seed2, ctx->HashOutputLength) != 0);
        if (updateFreq > 0) {
            printf("\n");
            printf("Found: H^%llu(s) = H^(2*%llu)(s)\n", i, i);
            printf("Computing cycle length...\n");
        }

        printf("Computing cycle length!\n");
        do {
            ctx->H(ctx->s11, ctx->seed1);
            memcpy(ctx->s11, ctx->seed1, ctx->HashOutputLength);
            l++;
            if (updateFreq > 0 && l % updateFreq == 0) {
                printf("Current Iteration: %llu\r", l);
            }
        } while (memcmp(ctx->seed1, ctx->seed2, ctx->HashOutputLength) != 0);
        if (updateFreq > 0) {
            printf("\nCycle length: %llu\n", l);
            printf("Resetting and repeating cycle length times to check for \"theoretical collision\".");
        }

        // Reset
        memcpy(ctx->seed1, ctx->init, ctx->HashOutputLength);
        memcpy(ctx->s11, ctx->init, ctx->HashOutputLength);
        memcpy(ctx->seed2, ctx->init, ctx->HashOutputLength);
        memcpy(ctx->s21, ctx->init, ctx->HashOutputLength);

        // Repeating cycle length times.
        for (i = 0; i < l; i++) {
            ctx->H(ctx->s21, ctx->seed2);
            memcpy(ctx->s21, ctx->seed2, ctx->HashOutputLength);
            if (updateFreq > 0 && i % updateFreq == 0) {
                printf("Progress: %llu / %llu (%.2lf%%)\r", i, l, (double) i / l * 100);
            }
        }
        if (updateFreq > 0) {
            printf("\n");
        }

        if (memcmp(ctx->init, ctx->seed2, ctx->HashOutputLength) == 0) {
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
            memcpy(ctx->s12, ctx->seed1, ctx->HashOutputLength);
            memcpy(ctx->s22, ctx->seed2, ctx->HashOutputLength);

            ctx->H(ctx->s11, ctx->seed1);
            memcpy(ctx->s11, ctx->seed1, ctx->HashOutputLength);
            ctx->H(ctx->s21, ctx->seed2);
            memcpy(ctx->s21, ctx->seed2, ctx->HashOutputLength);
            i++;

            if (updateFreq > 0 && i % updateFreq == 0) {
                printf("Current Iteration: %llu\r", i);
            }
        } while (memcmp(ctx->seed1, ctx->seed2, ctx->HashOutputLength) != 0);
        if (updateFreq > 0) {
            printf("\n");
            printf("Seed 1: ");
            printHexArray(ctx->s12, ctx->HashOutputLength);
            printf("\nSeed 2: ");
            printHexArray(ctx->s22, ctx->HashOutputLength);
            printf("\n");
        }

        memcpy(ctx->seed1, ctx->s12, ctx->HashOutputLength);
        memcpy(ctx->seed2, ctx->s22, ctx->HashOutputLength);

        if (updateFreq > 0) {
            printf("Checking for the last time if they give the same result.\n");
        }
        ctx->H(ctx->seed1, ctx->s11);
        ctx->H(ctx->seed2, ctx->s21);

        if (memcmp(ctx->s11, ctx->s21, ctx->HashOutputLength) == 0) {
            if (updateFreq > 0) {
                printf("Hash: ");
                printHexArray(ctx->s11, ctx->HashOutputLength);
                printf("\nHash Collision!!!\n");
            }
            return 0;
        } else {
            if (updateFreq > 0) {
                printf("False alarm :(\n");
            }
            return -1;
        }
    }
}