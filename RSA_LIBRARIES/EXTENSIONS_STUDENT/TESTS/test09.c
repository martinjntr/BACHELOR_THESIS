/*
---------------------------------------------------------------------------------------------------------------
 Filename: test09.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 05.06.2022
 Version: 1.1
 Description: Test generate RSA keys[1024 bit] and make some tests RSA encryption, decryption for each RSA key.
              Messages in tests are generated randomly.

 ---------------------------------------------------------------------------------------------------------------
*/
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include "../include/ext_rsa.h"
#include "../include/ext_file.h"


#define TEST_TOTAL_COUNT 100    /* Number of total tests [count of how many keys will be generated] */
#define TEST_RSA_COUNT 40       /* Number of test with one RSA key pair */

#define RSA_MOD_SIZE 1024       /* RSA modulus size in bits */

#ifdef BIT32
    #define RSA_MOD_SIZE_FORMAT (RSA_MOD_SIZE/32) /* RSA modulus size for 32-bit format, meaning RSA_MOD_SIZE/32  */
#elif defined BIT8
    #define RSA_MOD_SIZE_FORMAT (RSA_MOD_SIZE/8) /* RSA modulus size for 8-bit format, meaning RSA_MOD_SIZE/8  */
#endif

#define MAX_VAL (RSA_MOD_SIZE/8 - 2 * SHA1_BLOCK_SIZE -20) /* Maximum length of random generated message in bits*/


int main(){

/* Fields for storing result, enc and dec fields must be length of RSA_MOD_SIZE_FORMAT */
#ifdef BIT32
    uint32_t message [RSA_MOD_SIZE_FORMAT]; 
    uint32_t enc     [RSA_MOD_SIZE_FORMAT];
    uint32_t dec     [RSA_MOD_SIZE_FORMAT];
#elif defined BIT8
    uint8_t message [RSA_MOD_SIZE_FORMAT];
    uint8_t enc     [RSA_MOD_SIZE_FORMAT];
    uint8_t dec     [RSA_MOD_SIZE_FORMAT];
#endif

    int length;
    int res,err,sk;
    int random;

    rsa_key key;
    bignum m;

    for(int i=0; i<TEST_TOTAL_COUNT; i++){ /* Number of iteration, one itertion = one generate of key pair */
        err = key_gen(&key,RSA_MOD_SIZE);  /* Generate RSA key pair[public, private] length of RSA_MOD_SIZE  */ 

        if(err == -1){
            printf("Error occurs: RSA key generate\n");
            return 1;
        }     

        for(int x=0;x<TEST_RSA_COUNT; x++){ /* Number of RSA test with one generated RSA key pair */
            
            do{
                random = rand() % (MAX_VAL*8); /* Random length of message in bits */
            }while(random == 0);

            m=generate_secure_random(random); /* Random generated message of [random] length */
            length = bignum2msg(m,message,m.size); /* Convertion bignum to message and returns length of message*/

            if(length <=0){
                printf("Error occurs: convert bignum to msg\n");
                RSA_key_free(&key);
                free(m.tab);
                return 1;
            }

           /* Encrypt message of length size and store result to enc, RSA encryption with OAEP PKCS1 PADDING */
           res =  RSA_encrypt(message,length,key.pub,enc,RSA_MOD_SIZE,OAEP_PKCS1_PADDING);
           if(res <=0 ){
               printf("Error occurs: RSA encrypt\n");
               RSA_key_free(&key);
               free(m.tab);
               return 1;
           }

            /* Decrypt message stored in enc and store result to dec, 
               RSA decryption with OAEP PKCS1 PADDING, function return length of message */
           sk =  RSA_decrypt(enc,key.priv,dec,RSA_MOD_SIZE,OAEP_PKCS1_PADDING);
           
           if(sk != length){ /* Check for result if original message has same lenght as decrypted */
               printf("Error occurs: RSA decrypt\n");
               RSA_key_free(&key);
               free(m.tab);
               return 1;
           }

           
           for(int p=0; p<length; p++){ /* Check if original message members are same as decrypted members */
               if(message[p] != dec[p]){
                   printf("Error occurs: RSA decrypt\n");
                   RSA_key_free(&key);
                   free(m.tab);
               return 1; 
               }
           }

           free(m.tab);
        }
        
        /* Print continuos passed RSA key tests*/
        printf("TEST RSA KEY: %d/%d PASSED\n",i+1,TEST_TOTAL_COUNT);
        RSA_key_free(&key);
    }

    printf("SUCCESS\n");

    return 0;
}