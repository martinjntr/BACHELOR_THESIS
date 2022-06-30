
/*
---------------------------------------------------------------------------
 Filename: test02.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 24.05.2022
 Version: 1.3

Description: 1. Generate RSA key pair 
             2. Encrypt with RSA-OAEP
             3. Decrypt with RSA-OAEP

---------------------------------------------------------------------------
*/


#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define BILLION 1000000000L

#define MODULUS_COUNT 3
#define MLEN 16

int main(void) {

	uint8_t M[MLEN];

	// Random message
	for(int i=0; i<MLEN; i++){
		M[i] = rand() % 254 + 1;
	}

	unsigned long	e = RSA_F4; // 4-Fermat number 65 537
	uint32_t MODULUS_SIZE[MODULUS_COUNT] = {1024, 2048, 4096};

	BIGNUM	*bne = NULL;
	RSA		*r = NULL;

	uint8_t *enc, *dec;
	int ret, res;

	bne = BN_new();

	// bne = e
	ret = BN_set_word(bne,e);
	if(ret != 1){
		//goto free_all;
	}

	double diff;
    struct timespec start, end;

	for(int i=0; i<MODULUS_COUNT; i++){
		enc = (uint8_t*) malloc(MODULUS_SIZE[i]/8);
		dec = (uint8_t*) malloc(MODULUS_SIZE[i]/8);

		r = RSA_new();

		// RSA key generate
		ret = RSA_generate_key_ex(r, MODULUS_SIZE[i], bne, NULL);
		if(ret != 1){
			return -1;
		}

		clock_gettime(CLOCK_MONOTONIC, &start);

		// Encrypt RSA + OAEP
		res = RSA_public_encrypt(MLEN,M,enc,r,RSA_PKCS1_OAEP_PADDING);
		if(res < 0){
			printf("Encryption error\n");
			return 1;
		}
		
		clock_gettime(CLOCK_MONOTONIC, &end);

		diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
    	printf("Encryption [%d bits RSA modulus]: elapsed time = %lf seconds\n", MODULUS_SIZE[i],diff);

		clock_gettime(CLOCK_MONOTONIC, &start);

		// Decrypt RSA + OAEP
		ret = RSA_private_decrypt(res,enc,dec,r,RSA_PKCS1_OAEP_PADDING);
		if(ret < 0){
			printf("Decryption error\n");
			return 1;
		}
		clock_gettime(CLOCK_MONOTONIC, &end);

		diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
    	printf("Decryption [%d bits RSA modulus]: elapsed time = %lf seconds\n\n", MODULUS_SIZE[i],diff);


		if(memcmp(M,dec, MLEN) != 0 ){
			printf("Error\n");
			return 1;
		}

		RSA_free(r);

		free(enc);
		free(dec);
	}

   
	BN_free(bne);

    return 0;
}
