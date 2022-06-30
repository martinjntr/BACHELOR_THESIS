/*
---------------------------------------------------------------------------
 Filename: test03.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 24.05.2022
 Version: 1.3

Description: 1. Encrypt message with OAEP
             2. Decrypt message with OAEP

---------------------------------------------------------------------------
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <time.h>
#include "../extensions_mcrypto.h"


#define MLEN 20
#define SEED 4

// RSA mod length represented for DIGIT_T format
#define MOD_SIZE (1024/BITS_PER_DIGIT)
#define MOD_LEN_BYTES (1024/8)


int main(){

    PKCS1_RSA_PUBLIC_KEY spk;
    PKCS1_RSA_PRIVATE_KEY ssk;
    spk.len = MOD_SIZE;
    ssk.len = MOD_SIZE;

    uint8_t M[MLEN];
    uint8_t _M[MLEN];
    uint8_t EM[MOD_LEN_BYTES];

    UINT _mlen;

    // Init linear congruent generator
    srand(SEED);

    // Random gnerated message
    for(int i=0; i<MLEN; i++){
        M[i] = rand() % 254 + 1;
    }

    // Encryption with OAEP
    int res = PKCS1_EME_OAEP_ENC(&spk, HASH_SHA1,M,MLEN,NULL,0,EM);
    if(res != ERR_OK){
        printf("Encrypt error \n");
        return 1;
    }

    res =  PKCS1_EME_OAEP_DEC(&ssk,HASH_SHA1, EM, NULL, 0, _M,&_mlen);
      if(res != ERR_OK){
        printf("Decrypt error \n");
        return 1;
    }

    if(memcmp(M,_M,MLEN) || MLEN != _mlen){
        printf("Error\n");
    }

    return 0;
}