#ifndef _RAND_GF2NX_H
#define _RAND_GF2NX_H
#include "gf2nx.h"
#include "parameters_HFE.h"



void PQCLEAN_GEMSSRED128_CLEAN_randMonic_gf2nx(gf2nx F, unsigned int d);
void PQCLEAN_GEMSSRED128_CLEAN_randMonicHFE_gf2nx(sparse_monic_gf2nx F);



void PQCLEAN_GEMSSRED128_CLEAN_randMonicHFEv_gf2nx(sparse_monic_gf2nx F);


void PQCLEAN_GEMSSRED128_CLEAN_cleanMonicHFE_gf2nx(sparse_monic_gf2nx F);


void PQCLEAN_GEMSSRED128_CLEAN_cleanMonicHFEv_gf2nx(sparse_monic_gf2nx F);


#endif
