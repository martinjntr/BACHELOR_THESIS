/*
---------------------------------------------------------------------------
 Filename: test06.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 05.06.2022
 Version: 1.3

Description: - test encrypt ande decrypt message with OAEP
---------------------------------------------------------------------------
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "oaep.h"
#include "../HASH/EXTENSIONS/ext_sha.h"

#define BILLION 1000000000L

#define MLEN 20
#define SEED 4

// Modulus size in bits
#define MOD_SIZE (1024/8) 

int main(){

    uint8_t   M[MLEN];
    uint8_t  _M[MLEN];
    uint8_t  EM[MOD_SIZE];

    HASH_FUNCTION HASH= SHA1_FUNC;


    double diff;
    struct timespec start, end;

    srand(SEED);
    /*
     Random generate message based on SEED value for
     rand() generator
    */
    for(int i=0; i<MLEN; i++){
        M[i] = rand() % 254 + 1;
    }

    // Encrypt with OAEP
    clock_gettime(CLOCK_MONOTONIC, &start);
    int res = oaep_encode(M,MLEN,MOD_SIZE,NONE,EM,HASH);
    if (res !=0){
        printf("Error\n");
        return 1;
    }

    // Decrypt with OAEP
    res = oaep_decode(EM,MOD_SIZE,NONE,HASH,_M);
    if( res <=0){
        printf("Error\n");
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
    printf("Encryption and decryption EME-OAEP: elapsed time = %lf seconds\n", diff);

    // Check  M == _M
    if(memcmp(M,_M,MLEN) != 0 ){
        printf("Error\n");
        return 1;
    }

    return 0;
}