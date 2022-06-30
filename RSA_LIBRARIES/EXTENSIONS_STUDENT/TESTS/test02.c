/*
---------------------------------------------------------------------------
 Filename: test02.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 24.05.2022
 Version: 1.2

Description: - test realize encyption and decription process with RSA+OAEP
 
Test generates key pair of length:
        1024 bits 
        2048 bits 
        4096 bits 
And test RSA + OAEP encryption and decryption of each key

---------------------------------------------------------------------------
*/


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "../include/ext_rsa.h"
#include "../include/ext_file.h"

#define BILLION 1000000000L

#define SEED 3
#define MLEN 16

#define MODULUS_COUNT 3

int main(void){

    srand(SEED);
    var TEST_MESSAGE[MLEN];

    for(int i=0; i<MLEN; i++){ // Random message generate
        TEST_MESSAGE[i] = rand() % 254 + 1;  
    }

    // Modulus length
    uint32_t rsa_modulus_size[MODULUS_COUNT] = {1024,2048,4096};


    /*Reading message from file and store to address of pointer message, 
     message pointer will contain message of mlen length, function return length of message */

    rsa_key key;
    int err, res;
    var *enc, *dec;
    
    double diff;
    struct timespec start, end;

    
    for(int i=0; i< MODULUS_COUNT; i++){

        // RSA generate key
        printf("Generating: %d bits RSA key\n\n", rsa_modulus_size[i]);
        err = key_gen(&key, rsa_modulus_size[i]);
        if(err !=0){
            printf("Key genrate error \n");
            return 1;
        } 
        
        enc = (var*) malloc(key.pub.n.size * 8);
        dec = (var*) malloc(key.pub.n.size * 8);


        clock_gettime(CLOCK_MONOTONIC, &start);

        /* Encrypt message of mlen length and store result to enc, RSA encryption with OAEP PKCS1 PADDING */
        err = RSA_encrypt(TEST_MESSAGE, MLEN,key.pub,enc,rsa_modulus_size[i],OAEP_PKCS1_PADDING);
        if(err <=0){
            printf("Error occurs: RSA encrypt problem\n");
            RSA_key_free(&key);
            return 1;
        } 

        clock_gettime(CLOCK_MONOTONIC, &end);
        diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
        printf("Encryption [%d bits RSA modulus]: elapsed time = %lf seconds\n", rsa_modulus_size[i],diff);
    
    
        clock_gettime(CLOCK_MONOTONIC, &start);
        /* Decrypt message stored in enc and store result to dec, 
        RSA decryption with OAEP PKCS1 PADDING, function return length of message */
        
        res = RSA_decrypt(enc,key.priv,dec,rsa_modulus_size[i],OAEP_PKCS1_PADDING);
        clock_gettime(CLOCK_MONOTONIC, &end);
        diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
        printf("Decryption [%d bits RSA modulus]: elapsed time = %lf seconds\n", rsa_modulus_size[i],diff);
        printf("--------------------------------------------------------------------------------\n\n");
        if(res < 0 || (res != MLEN)){ /* Check for result if original message has same lenght as decrypted */
            printf("Error occurs: RSA decrypt problem\n");
            RSA_key_free(&key);
            return 1;
        }

        for(int i=0;i<res;i++){ /* Check if original message members are same as decrypted members */
            if(dec[i] != TEST_MESSAGE[i]){
                printf("Error occurs: message and result comparation problem\n");
                RSA_key_free(&key);
                return 1;
            }
        }

        RSA_key_free(&key); /* Destroy public and private key */
    }


    printf("SUCCESS\n");

  return 0;
}