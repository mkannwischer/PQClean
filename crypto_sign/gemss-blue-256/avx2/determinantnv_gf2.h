#ifndef _DETERMINANTNV_GF2_H
#define _DETERMINANTNV_GF2_H
#include "arch.h"
#include "gf2.h"
#include "matrix_gf2.h"



gf2 PQCLEAN_GEMSSBLUE256_AVX2_determinantnv_nocst_gf2(cst_Mnv_gf2 S, Mnv_gf2 S_cp);

gf2 PQCLEAN_GEMSSBLUE256_AVX2_determinantnv_cst_gf2(cst_Mnv_gf2 S, Mnv_gf2 S_cp);


#define determinantnv_gf2 PQCLEAN_GEMSSBLUE256_AVX2_determinantnv_cst_gf2


#endif
