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

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define BILLION 1000000000L

#define SEED 4
#define SIZE 1

// Modulus len size array
#define MOD_SIZE 128 
// MAX value for uint8_t
#define MAX_VAL 255
#define TEST_COUNT 30

int main(void) {
    uint8_t e[SIZE];
    uint8_t m[SIZE];
    srand(SEED);

    m[0] = rand() % 254 + 1;
    e[0] = rand() % 254 + 1;

    uint8_t n[MOD_SIZE];
    for(int i=0; i<MOD_SIZE;i++){
        n[i] = MAX_VAL;
    }

    // _m = m
    BIGNUM *_m = BN_bin2bn(m, 1, NULL);

    // _e = e
    BIGNUM *_e = BN_bin2bn(e, 1, NULL);

    //_n = n
    BIGNUM *_n = BN_bin2bn(n, sizeof(n), NULL);
    BIGNUM *c = BN_new();
    BN_CTX *ctx = NULL;

    double diff;
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    for(int i=0; i< TEST_COUNT; i++){
        ctx = BN_CTX_new();
        BN_mod_exp(c, _m, _e, _n, ctx); // c =  m^e mod n
        BN_mod_exp(_e, _m, c, _n, ctx); // e =  m^c mod n 
        BN_mod_exp(_m, c, _n, _e, ctx); // m =  c^n mod e
        BN_mod_exp(_n, c, _e, _m, ctx); // n =  c^e mod m
        BN_CTX_free(ctx);
    }


    clock_gettime(CLOCK_MONOTONIC, &end); 
    diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
    printf("elapsed time = %lf seconds\n\n", diff);
    // create context

    char *s1 = BN_bn2hex(_m);   
    printf("%s\n", s1);

    OPENSSL_free(s1);

    // Free memory
    BN_free(c);
    BN_free(_m);
    BN_free(_e);
    BN_free(_n);
   
    return 0;
}
