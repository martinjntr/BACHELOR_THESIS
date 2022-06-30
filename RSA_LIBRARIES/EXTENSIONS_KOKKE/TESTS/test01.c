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

#include "ext_rsa.h"

#define BILLION 1000000000L

#define SEED 4
#define TEST_COUNT 30 /* Number of algorithm test */

int main()
{
    struct bn m,e,n,c;
    
    /* Set init value 0 to variables */
    bignum_init(&m);
    bignum_init(&e);
    bignum_init(&n);
    bignum_init(&c);


    /* Set starting SEED value for linear congruent generator */
    srand(SEED); 

    m.array[0]= rand() % 254 + 1;  /* random value in range [1 - 255]*/
    e.array[0]= rand() % 254 + 1;

    for(int i=0;i<BN_ARRAY_SIZE/2;i++){ /* Assign MAX value modulus to BN */
        n.array[i] = UINT32_MAX;
    }

    double diff;
    struct timespec start, end;

    printf("TEST STARTING ...\n");
    clock_gettime(CLOCK_MONOTONIC, &start);  /* Start time measurement */

    for(int i=0;i<TEST_COUNT;i++)
    {
        pow_mod_faster(&m,&e,&n,&c);    /* c = m^e mod n */
        pow_mod_faster(&m,&c,&n,&e);    /* e = m^c mod n */
        pow_mod_faster(&c,&n,&e,&m);    /* m = c^n mod e */
        pow_mod_faster(&c,&e,&m,&n);    /* n = c^e mod m */
    }

    clock_gettime(CLOCK_MONOTONIC, &end);  /* End time measurement */

    /* count elapsed time */
    diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
    printf("elapsed time = %lf seconds\n\n", diff);

    print_BN(&m);

    printf("\n\nTEST WAS PASSED SUCCESS !!!\n");
    return 0;
}