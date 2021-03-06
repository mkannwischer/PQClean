#ifndef _PARAMETERS_HFE_H
#define _PARAMETERS_HFE_H
#include "choice_crypto.h"


/****************** PARAMETERS FOR HFE ******************/


/** GF(q) */
#define GFq 2U
#define Log2_q 1
/* For HFE, the previous parameter is necessarily 2. */



/* Number of variables of the public-key */
#define HFEnv (HFEn+HFEv)

/* Number of equations of the public-key */
#define HFEm (HFEn-HFEDELTA)



/* RedGeMSS128 */

#define HFEn 177U
#define HFEv 15U
#define HFEDELTA 15U

#define NB_ITE 4U

#define HFEDeg 17U
#define HFEDegI 4U
#define HFEDegJ 0U

#define HFEs 0U

/* RedGeMSS192 */



/****************** VERIFICATION OF THE PARAMETERS ******************/


/* X^(2^i + 2^j) >= X^(2^n) */




#endif
