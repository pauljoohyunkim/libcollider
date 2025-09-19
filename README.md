# libcollider
Hash collision library

```
// Sample Code
// hashfun is of type: void hashfun(const uint8_t input[LEN], uint8_t output[LEN])
uint8_t init[SEED_KEY_LEN] = { 0x31, 0xB7, 0xFA, 0x4B, 0xA8, 0x1C, 0x59, 0xA8 };
uint8_t seed1[SEED_KEY_LEN] = { 0 };
uint8_t seed2[SEED_KEY_LEN] = { 0 };
uint8_t s11[SEED_KEY_LEN] = { 0 };
uint8_t s12[SEED_KEY_LEN] = { 0 };
uint8_t s21[SEED_KEY_LEN] = { 0 };
uint8_t s22[SEED_KEY_LEN] = { 0 };
Collider_CTX ctx = { .cycle.H = hashfun,
    .cycle.init = init,
    .cycle.randomizeInit = true,
    .cycle.HashOutputLength = LEN,
    .cycle.seed1 = seed1,
    .cycle.seed2 = seed2,
    .cycle.s11 = s11,
    .cycle.s12 = s12,
    .cycle.s21 = s21,
    .cycle.s22 = s22
};
// Update every 100000 iterations.
// Setting updateFreq to zero suppresses all outputs.
cycleAttack(&ctx, 100000);
```