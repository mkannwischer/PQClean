#ifndef _GENSECRETMQS_GF2_H
#define _GENSECRETMQS_GF2_H
#include "MQS_gf2.h"
#include "arch.h"
#include "gf2nx.h"



int PQCLEAN_GEMSSBLUE128_AVX2_genSecretMQS_gf2_ref(mqsnv_gf2n MQS, cst_sparse_monic_gf2nx F);
int PQCLEAN_GEMSSBLUE128_AVX2_genSecretMQS_gf2_opt(mqsnv_gf2n MQS_res,
        cst_sparse_monic_gf2nx F);



#define genSecretMQS_gf2 PQCLEAN_GEMSSBLUE128_AVX2_genSecretMQS_gf2_opt


#endif
