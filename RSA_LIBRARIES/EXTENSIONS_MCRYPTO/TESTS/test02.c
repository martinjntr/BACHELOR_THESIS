/*
---------------------------------------------------------------------------
 Filename: test02.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 24.05.2022
 Version: 1.3

Description: 1. Generate RSA key pair 
             2. Encrypt with RSA-OAEP
             3. Decrypt with RSA-OAEP

---------------------------------------------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../extensions_mcrypto.h"

#define BILLION 1000000000L

#define SEED 3
#define MLEN 16

// MODULUS size based on defined value
#define RSA_MOD_LEN (MAX_DIG_LEN) 
#define RSA_OAEP_LEN (MOD_LEN/8)

int main(){

    BYTE M [MLEN];

    srand(SEED); // Init linear congruent generator

    // Random message
    for(int i=0; i<MLEN; i++){
        M[i] = rand() % 254 + 1;
    }

    PKCS1_RSA_KEY key;

    // Generate RSA key pair
    UINT err = PKCS1_RSA_GenKey(&key.public_key,&key.private_key,RSA_MOD_LEN);

    BYTE ENC[RSA_OAEP_LEN];
    BYTE DEC[RSA_OAEP_LEN];

    UINT res, _mlen;

    double diff;
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    // RSA + OAEP Encryption
    res = PKCS1_RSA_OAEP_ENCRYPT(&key.public_key, HASH_SHA1,M, MLEN, NULL, 0, ENC);
    if(res != ERR_OK){
        printf("Encrypt error \n");
        return 1;
    }


    clock_gettime(CLOCK_MONOTONIC, &end);
    diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
    printf("Encryption [%d bits RSA modulus]: elapsed time = %lf seconds\n", MOD_LEN,diff);


    clock_gettime(CLOCK_MONOTONIC, &start);

    // RSA + OAEP Decryption
    res= PKCS1_RSA_OAEP_DECRYPT(&key.private_key, HASH_SHA1,ENC, NULL, 0, DEC, &_mlen);
      if(res != ERR_OK){
        printf("Decrypt error \n");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
    printf("Decryption [%d bits RSA modulus]: elapsed time = %lf seconds\n", MOD_LEN,diff);
    
    if(memcmp(M,DEC,MLEN)!=0 || _mlen != MLEN){
        printf("Error");
        return 1;
    }

    return 0;
}