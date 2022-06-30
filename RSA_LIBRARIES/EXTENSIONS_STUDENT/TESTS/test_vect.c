

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
#include <stdint.h>
#include <time.h>
#include "../include/ext_rsa.h"
#include "../include/ext_file.h"

#define RSA_MOD_SIZE 1024

int main(void){


/* Message in HEX format with length of MLEN*/
#ifdef BIT32
  uint32_t MLEN = 4;
  uint32_t message[MLEN] = {
      0xd436e995,0x69fd32a7
      0xc8a05bbc,0x90d32c49
    }; 
#elif defined BIT8
  uint32_t MLEN = 16;
  uint8_t message[MLEN] = {
    0xd4,0x36,0xe9,0x95,0x69,
    0xfd,0x32,0xa7,0xc8,0xa0,
    0x5b,0xbc,0x90,0xd3,0x2c,0x49
    };
#endif


    /*Reading message from file and store to address of pointer message, 
     message pointer will contain message of mlen length, function return length of message */

    rsa_key key;
    int err = key_gen(&key, RSA_MOD_SIZE);

    
    /* Memory for storing results and  */
    #ifdef BIT8
        /* RSA modulus size in bits */
        uint32_t RSA_MOD_SIZE = key.pub.n.size * 8; 
        /* Maximum length of message, it is for when SHA1 hash function is used */
        uint32_t max_msg_len =  key.pub.n.size - 2*SHA1_BLOCK_SIZE -1; 

        uint8_t enc[RSA_MOD_SIZE/8];
        uint8_t dec[RSA_MOD_SIZE/8];

    #elif defined BIT32
         /* RSA modulus size in bits */
        uint32_t RSA_MOD_SIZE = (key.pub.n.size * 8) * sizeof(var);
        /* Maximum length of message, it is for when SHA1 hash function is used */
        uint32_t max_msg_len =  key.pub.n.size - (2*SHA1_BLOCK_SIZE -1)/sizeof(var); 

        uint32_t enc[RSA_MOD_SIZE/32];
        uint32_t dec[RSA_MOD_SIZE/32];

    #endif

    /* Encrypt message of mlen length and store result to enc, RSA encryption with OAEP PKCS1 PADDING */
   int err = RSA_encrypt(message, MLEN,key.pub,enc,RSA_MOD_SIZE,OAEP_PKCS1_PADDING);
    
    
    if(err <=0){
        printf("Error occurs: RSA encrypt problem\n");
        free(message);
        RSA_key_free(&key);
        return 1;
    }
    
     /* Decrypt message stored in enc and store result to dec, 
        RSA decryption with OAEP PKCS1 PADDING, function return length of message */
   int res = RSA_decrypt(enc,key.priv,dec,RSA_MOD_SIZE,OAEP_PKCS1_PADDING);
    
    if(res < 0 || (res != mlen)){ /* Check for result if original message has same lenght as decrypted */
        printf("Error occurs: RSA decrypt problem\n");
        free(message);
        RSA_key_free(&key);
        return 1;
    }

    for(int i=0;i<res;i++){ /* Check if original message members are same as decrypted members */
        if(dec[i] != message[i]){
            printf("Error occurs: message and result comparation problem\n");
            free(message);
            RSA_key_free(&key);
            return 1;
        }
    }

    free(message);
    RSA_key_free(&key); /* Destroy public and private key */
    printf("SUCCESS\n");



  return 0;
}