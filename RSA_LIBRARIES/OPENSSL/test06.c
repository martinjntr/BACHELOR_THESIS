/*
---------------------------------------------------------------------------
 Filename: test06.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 24.05.2022
 Version: 1.2

Description: - test encrypt ande decrypt message with OAEP
---------------------------------------------------------------------------
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define BILLION 1000000000L

#define MLEN 20

// Modulus size 1024
#define MOD_SIZE 128
#define SEED 4

int main(){


    uint8_t M[MLEN];
    uint8_t _M[MLEN];
    uint8_t EM[MOD_SIZE];

    double diff;
    struct timespec start, end;

    srand(SEED);

    // Rnadom message generate based on SEED value
    for(int i=0; i<MLEN; i++){
        M[i] = rand() % 254 + 1;
    }

    // OAEP encryption
    clock_gettime(CLOCK_MONOTONIC, &start);
    int res = RSA_padding_add_PKCS1_OAEP(EM,MOD_SIZE,M,MLEN,NULL,0);

    if(res != 1) printf("Error\n");

    // OAEP decryption
    res = RSA_padding_check_PKCS1_OAEP(_M,MLEN,EM,MOD_SIZE,MOD_SIZE,NULL,0);
    clock_gettime(CLOCK_MONOTONIC, &end);

    diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
    printf("Encryption EME-OAEP: elapsed time = %lf seconds\n", diff);

    if(memcmp(M,_M,MLEN)){
        printf("Error\n");
        return 1;
    }
    return 0;
}