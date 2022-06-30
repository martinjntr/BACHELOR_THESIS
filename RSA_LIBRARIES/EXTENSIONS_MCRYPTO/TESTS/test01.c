/*
---------------------------------------------------------------------------
 Filename: test01.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 24.05.2022
 Version: 1.0

Description: - test realize checking aritmetic math operation with alogithm
             - test measure time for solving this algorithm

- Algorithm:

            m[0] - rand() % 254 + 1 range [1-255]
            e[0] - rand() % 254 + 1 range [1-255]

            n -> max value

            for[0 to TEST_COUNT]{
               c =  m^e mod n
               e =  m^c mod n 
               m =  c^n mod e
               n =  c^e mod m
            }

- For better chceck you can change TEST_COUNT to higher number

---------------------------------------------------------------------------
*/


#include <stdio.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../extensions_mcrypto.h"

/* Length of modulus */
#define MODULUS_LEN (1024/BITS_PER_DIGIT) 

#define BILLION 1000000000L

#define SEED 4
#define TEST_COUNT 30 /* Number of algorithm test */

int main(int argc,char** argv){

  int err;

  DIGIT_T m[MODULUS_LEN];
  DIGIT_T e[MODULUS_LEN];
  DIGIT_T n[MODULUS_LEN];
  DIGIT_T c[MODULUS_LEN];
  DIGIT_T tmp[MODULUS_LEN];

  /* Set array to 0 */
  mpSetZero(m,MODULUS_LEN);
  mpSetZero(e,MODULUS_LEN);  
  mpSetZero(n,MODULUS_LEN);  
  mpSetZero(c,MODULUS_LEN);
  mpSetZero(tmp,MODULUS_LEN);

  srand(SEED);

  /* random number based on SEED value */
  m[0] = rand() % 254 + 1;
  e[0] = rand() % 254 + 1;


  /* Assign MAX values to array */
  for(int i=0;i<MODULUS_LEN;i++){
    n[i] = MAX_DIGIT;
  }

  double diff;
  struct timespec start, end;

  clock_gettime(CLOCK_MONOTONIC, &start);  /* Start time measurement */


  for(int i=0;i<TEST_COUNT;i++){
    err = mpModExp(c,m,e,n,MODULUS_LEN); // c = m^e mod n
    if(err != 0){
      printf("Error");
      return 1;
    }

    err =mpModExp(e,m,c,n,MODULUS_LEN);  //  e =  m^c mod n 
     if(err != 0){
      printf("Error");
      return 1;
    }
    err =mpModExp(m,c,n,e,MODULUS_LEN);  // m =  c^n mod e
     if(err != 0){
      printf("Error");
      return 1;
    }

    err =mpModExp(n,c,e,m,MODULUS_LEN);  // n =  c^e mod m
     if(err != 0){
      printf("Error");
      return 1;
    }

    if(err != 0) return -1;
  }

  clock_gettime(CLOCK_MONOTONIC, &end);  /* End time measurement */

  /* count elapsed time */
  diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
  printf("elapsed time = %lf seconds\n\n", diff);

  mpPrint(m,MODULUS_LEN);

  printf("\n\nTEST WAS PASSED SUCCESS !!!\n");
 
  return 0;

    
}