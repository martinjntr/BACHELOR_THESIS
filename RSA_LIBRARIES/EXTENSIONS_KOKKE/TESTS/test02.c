/*
---------------------------------------------------------------------------
 Filename: test02.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 24.05.2022
 Version: 1.2

Description: - test realize encyption and decription process with RSA+OAEP
             - test is programmed for any size of RSA mosulus, 
              you can compile it with predefined values located in
              KOKKE bn.h, change value MOD_LEN

- If you comile this test dont forget for change MACRO MOD_LEN (bn.h):
 
 1024 bits -> 256
 2048 bits -> 512
 4096 bits -> 1024

 Or look into makefile

---------------------------------------------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ext_file.h"
#include "ext_rsa.h"

#define BILLION 1000000000L

#define MLEN 16   /* Length of message */

/* Starting value for linear congruent generator*/
#define SEED 3  

int main(int argc, char** argv)
{
  uint8_t message[MLEN];

  srand(SEED);

  for(int i=0; i<MLEN; i++){ /* Random message is generate */
      message[i] = rand() % 254 + 1;
  }
 
  RSA_KEY key;
  RSA_KEY_INIT(&key); /* Set all elements in RSA key to 0 */

  if(argc != 3){
    printf("Add filenames where is stored RSA key pair 1.Public key 2.Private key Using: test02 public_key.txt private_key.txt\n");
    return 1;
  }

  if(MOD_LEN >(BN_ARRAY_SIZE * WORD_SIZE)*4){ /* Check for overflow */
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
  uint8_t enc[MOD_LEN/8];
  uint8_t dec[MOD_LEN/8];

  double diff;
  struct timespec start, end;

  clock_gettime(CLOCK_MONOTONIC, &start); /* Start measure time */

  /* RSA + OAEP encryption*/
  err = RSA_ENCRYPT(message,MLEN,enc,&key.pub,MOD_LEN,OAEP_PKCS1_PADDING); 
  
  clock_gettime(CLOCK_MONOTONIC, &end); /* Stop measure time */

  /* Count result for encryption */
  diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
  printf("Encryption [%d bits RSA modulus]: elapsed time = %lf seconds\n", MOD_LEN,diff);
  
  if(err <=0){

    printf("Error occurs: RSA encrypt problem !!!\n");
    return 1;
  }
  

  clock_gettime(CLOCK_MONOTONIC, &start);

  /* RSA + OAEP decryption */
  int res = RSA_DECRYPT(enc,&key.priv,dec,MOD_LEN,OAEP_PKCS1_PADDING); /* RSA 1024-bit decrypt with no padding */
  
  clock_gettime(CLOCK_MONOTONIC, &end);

  /* Count result for decryption */
  diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
  printf("Decryption [%d bits RSA modulus]: elapsed time = %lf seconds\n", MOD_LEN,diff);
  
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