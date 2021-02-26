#ifndef PQCLEAN_GEMSSBLUE192_AVX2_API_H
#define PQCLEAN_GEMSSBLUE192_AVX2_API_H

#include <stddef.h>
#include <stdint.h>

#define PQCLEAN_GEMSSBLUE192_AVX2_CRYPTO_ALGNAME                      "gemss-blue-192"

#define PQCLEAN_GEMSSBLUE192_AVX2_CRYPTO_SECRETKEYBYTES               24
#define PQCLEAN_GEMSSBLUE192_AVX2_CRYPTO_PUBLICKEYBYTES               1264117
#define PQCLEAN_GEMSSBLUE192_AVX2_CRYPTO_BYTES                        53

int PQCLEAN_GEMSSBLUE192_AVX2_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_GEMSSBLUE192_AVX2_crypto_sign(uint8_t *sm, size_t *smlen, const uint8_t *msg, size_t len, const uint8_t *sk);
int PQCLEAN_GEMSSBLUE192_AVX2_crypto_sign_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk);
int PQCLEAN_GEMSSBLUE192_AVX2_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
int PQCLEAN_GEMSSBLUE192_AVX2_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);

#endif
