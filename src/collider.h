#ifndef COLLIDER_H_
#define COLLIDER_H_

#include <stdint.h>
#include <stdbool.h>

// h(input, output)
typedef void (*HashFunction)(const uint8_t[], uint8_t*);

typedef struct Collider_CTX {
    HashFunction H;
    uint8_t *init;
    bool randomizeInit;
    short HashOutputLength;
    union {
        struct {
            
        } birthday;

        struct {
            uint8_t *seed1;
            uint8_t *seed2;
            uint8_t *s11;
            uint8_t *s21;
            uint8_t *s12;
            uint8_t *s22;
        } cycle;
    };
} Collider_CTX;

int cycleAttack(Collider_CTX *ctx, unsigned long long updateFreq);

#endif  // COLLIDER_H_