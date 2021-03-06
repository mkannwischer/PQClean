#ifndef _SIGN_KEYPAIRHFE_H
#define _SIGN_KEYPAIRHFE_H
#include "arch.h"
#include <stdint.h>


/* Generates a keypair - pk is the public-key and sk is the secret-key. */
int PQCLEAN_GEMSSBLUE128_AVX2_sign_keypairHFE(uint8_t *pk, UINT *sk);


#endif
