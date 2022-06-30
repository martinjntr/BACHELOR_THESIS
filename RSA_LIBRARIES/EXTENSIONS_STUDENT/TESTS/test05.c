/*
---------------------------------------------------------------------------
 Filename: test05.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 24.05.2022
 Version: 1.2

Description: -test generate RSA keys of length [1024, 2048, 4096]
---------------------------------------------------------------------------
*/


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "../include/ext_rsa.h"
#include "../include/ext_file.h"

#define BILLION 1000000000L
#define RSA_MOD_COUNT 3

int main(void){

  // Length of modulus size in bits
  uint32_t RSA_MOD_SIZE [RSA_MOD_COUNT] = {1024,2048,4096};
  
  double diff;
  struct timespec start, end;

  rsa_key key;
  int err;

  for(int i=0; i<RSA_MOD_COUNT; i++){

    printf("Generating: %d bits RSA key\n", RSA_MOD_SIZE[i]);
    clock_gettime(CLOCK_MONOTONIC, &start);

    // RSA generate key 
    err = key_gen(&key,RSA_MOD_SIZE[i]);
  
    clock_gettime(CLOCK_MONOTONIC, &end); 

    diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
    printf("elapsed time = %lf seconds\n\n", diff);


    if(err != 0){
      printf("Error occurs: RSA key generate\n");
      return 1;
    }

    RSA_key_free(&key);
  }


  printf("SUCCESS\n");

  return 0;
}