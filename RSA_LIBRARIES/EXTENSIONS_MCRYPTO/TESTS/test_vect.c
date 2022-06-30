
/*
---------------------------------------------------------------------------
 Filename: test_vect.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 24.05.2022
 Version: 1.2

Description: - Test generate RSA key pair based or test vectors, 
               encrypt decrypt message and check if message was 
               succesfully encrypted and decrypted
             - Key is generated from test vectors:

https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf


---------------------------------------------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../extensions_bigdigits.h"

#define MLEN 16  /* Message length, speciffied in test vectrs */
#define RSA_MOD_LEN (MAX_DIG_LEN) /* RSA mod len */
 

int main(){
    /* Message from test vectors */
    BYTE M [MLEN] = {
        0xd4,0x36,0xe9,0x95,0x69,0xfd,0x32,0xa7,
        0xc8,0xa0,0x5b,0xbc,0x90,0xd3,0x2c,0x49
    };

    PKCS1_RSA_KEY key;
    /* Generate key */
    UINT err = PKCS1_RSA_GenKey(&key.public_key,&key.private_key,RSA_MOD_LEN);

    /* Needed memory space */
    BYTE ENC[RSA_OAEP_LEN]; 
    BYTE DEC[RSA_OAEP_LEN];

    UINT res, _mlen;
    /* Encrypt with RSA + OAEP*/
    res = PKCS1_RSA_OAEP_ENCRYPT(&key.public_key, HASH_SHA1,M, MLEN, NULL, 0, ENC);
    
    if(res != ERR_OK){
        printf("Encrypt error \n");
        return 1;
    }

    /* Decrypt with RSA + OAEP*/
    res= PKCS1_RSA_OAEP_DECRYPT(&key.private_key, HASH_SHA1,ENC, NULL, 0, DEC, &_mlen);

    if(res != ERR_OK){
        printf("Decrypt error \n");
        return 1;
    }

    if(memcmp(DEC,M) != 0 || _mlen != MLEN){
        printf("Error\n");
        return 1;
    }
    
    printf("\n\nTEST WAS PASSED SUCCESS !!!\n");

    return 0;
}