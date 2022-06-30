/*
---------------------------------------------------------------------------
 Filename: test03.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 24.05.2022
 Version: 1.3

Description: 1. Generate RSA key 1024 bit
             2. Generate RSA key 2048 bit
             3. Generate RSA key 4096 bit

---------------------------------------------------------------------------
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../extensions_mcrypto.h"

#define BILLION 1000000000L
// Moulus count in our example we use [1024, 2048, 4096]
#define RSA_MOD_COUNT 3  

int main(void){

  
    PKCS1_RSA_KEY key;
    UINT len, err;
    uint32_t RSA_MOD_SIZE [RSA_MOD_COUNT] = {1024,2048,4096};

    double diff;
    struct timespec start, end;

    

    for(int i=0; i<RSA_MOD_COUNT; i++){

        // Count length RSA mod size for function PKCS1_RSA_GenKey()
        len = RSA_MOD_SIZE[i] / BITS_PER_DIGIT; 
        printf("Generating: %d bits RSA key\n", RSA_MOD_SIZE[i]);
        clock_gettime(CLOCK_MONOTONIC, &start);

        // Generate RSA key
        err = PKCS1_RSA_GenKey(&key.public_key,&key.private_key,len);
        if(err != ERR_OK){
        printf("Key generation problem \n");
        return 1;
    }
        clock_gettime(CLOCK_MONOTONIC, &end); 

        diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
        printf("elapsed time = %lf seconds\n\n", diff);
    }

    printf("SUCCESS\n");





    return 0;
}