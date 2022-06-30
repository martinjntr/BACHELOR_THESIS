
/*
---------------------------------------------------------------------------
 Filename: test_vect.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 24.05.2022
 Version: 1.2

Description: - Test read public and private key from file and encrypt, 
              decrypt message and check if message was succesfully 
              encrypted and decrypted
             - Key is generated from test vectors:

https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf


---------------------------------------------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ext_file.h"
#include "ext_rsa.h"

#define MLEN 16   /* Length of message */
#define RSA_MODULUS 1024  /* Length of RSA modulus in bits */

int main(int argc, char** argv)
{

  /* Message from test vectors */
  uint8_t message[MLEN]= {0xd4,0x36,0xe9,0x95,0x69,0xfd,0x32,0xa7,0xc8,0xa0,0x5b,0xbc,0x90,0xd3,0x2c,0x49};
 
  RSA_KEY key;
  RSA_KEY_INIT(&key); /* Set all elements in RSA key to 0 */

  if(argc != 3){
    printf("Add filenames where is stored RSA key pair 1.Public key 2.Private key Using: test03 public_key.txt private_key.txt\n");
    return 1;
  }

  if(RSA_MODULUS >(BN_ARRAY_SIZE * WORD_SIZE)*4){
    printf("Modulus is bigger than BN_ARRAY_SIZE !!!\n");
    return 1;
  }
  
  int err;
  err = ReadRSA_KEY(argv[1],&key,PUBLIC); /* Reading public key and store to key variable */
  if(err){
   printf("Error occurs: RSA public key reading !!! \n");
   return 1;
  }

  err = ReadRSA_KEY(argv[2],&key,PRIVATE); /* Reading private key and store to key variable */
  if(err){
    printf("Error occurs: RSA private key reading !!! \n");
    return 1;
  }
  
  /* Fields for storing result of RSA encryption and decryption */
  uint8_t enc[RSA_MODULUS/8];
  uint8_t dec[RSA_MODULUS/8];

  err = RSA_ENCRYPT(message,MLEN,enc,&key.pub,RSA_MODULUS,OAEP_PKCS1_PADDING); /* RSA 1024-bit encrypt with no padding */
  if(err <=0){
    printf("Error occurs: RSA encrypt problem !!!\n");
    return 1;
  }
    
  int res = RSA_DECRYPT(enc,&key.priv,dec,RSA_MODULUS,OAEP_PKCS1_PADDING); /* RSA 1024-bit decrypt with no padding */
  if(res <=0){
    printf("Error occurs: RSA decrypt problem !!!\n");
    return 1;
  }

  if(res != MLEN){
        printf("Not success\n");
        return 1;
    }

  for(int i=0;i<res;i++){ /* Check if message was succesfull writen and read, x-> length of message */
    if(dec[i]!=message[i]){
        printf("Not success\n");
        return 1;
    }
  }

  printf("\n\nTEST WAS PASSED SUCCESS !!!\n");
  return 0;
}