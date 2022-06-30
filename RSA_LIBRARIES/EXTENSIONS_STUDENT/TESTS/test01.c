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
#include <stddef.h>
#include <time.h>

#include "../include/ext_bignum.h"

#define BILLION 1000000000L

#define SEED 4
#define TEST_COUNT 30 /* Number of algorithm test */

int main(){

bignum m,e,n,c;

m.size=1, e.size=1;
m.sign=1,e.sign=1, n.sign=1; /* Positive numbers */


/* Allocation memory */
m.tab=(block*) malloc(sizeof(block));
if(m.tab == NULL){
    printf("Allocation problem !!!\n");
    return 1;
} 

e.tab=(block*) malloc(sizeof(block));
if(e.tab == NULL){
    free(m.tab);
    printf("Allocation problem !!!\n");
    return 1;
}

srand(SEED);

// random values
m.tab[0] = rand() % 254 + 1;
e.tab[0] = rand() % 254 + 1;

#ifdef BIT8
    n.size = 128; /* Size of bignumber for 1024 bit modulus */
    n.tab = (block*) malloc(n.size * sizeof(block));

    if(n.tab == NULL){
        free(m.tab);
        free(e.tab);
        printf("Allocation problem !!!\n");
        return 1;
    } 

    for(int i=0;i<n.size;i++){
        n.tab[i]= UINT8_MAX; /* MAX value for one number in bignumber format */
    }
#elif defined BIT32
    n.size = 32; /* Size of bignumber for 1024 bit modulus */
    n.tab = (block*) malloc(n.size * sizeof(block));

    if(n.tab == NULL){
        free(m.tab);
        free(e.tab);
        printf("Allocation problem !!!\n");
        return 1;
    } 

    for(int i=0;i<n.size;i++){
        n.tab[i]= UINT32_MAX; /* MAX value for one number in bignumber format */
    }
#endif

double diff;
struct timespec start, end;

clock_gettime(CLOCK_MONOTONIC, &start);  /* Start time measurement */

    for(int i=0;i<TEST_COUNT;i++){
         c = expmod(m,e,n);     // c = m^e mod n
         free(e.tab);

         e = expmod(m,c,n);     // e = m^c mod n
         free(m.tab);

         m = expmod(c,n,e);     // m = c^n mod n
         free(n.tab);

         n = expmod(c,e,m);     // n = c^e mod n
         free(c.tab);

         /* When last cyclus occurs, c.tab memory wouldnt destroy we will use it on print */
         if(i == TEST_COUNT-1) continue; 
         //free(m.tab);
    }

clock_gettime(CLOCK_MONOTONIC, &end);  /* End time measurement */

/* count elapsed time */
diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
printf("elapsed time = %lf seconds\n\n", diff);
 
 /* Destroy memory*/
 free(n.tab);
 free(e.tab);
 print_bignum(m);
 free(m.tab);
    return 0;
}