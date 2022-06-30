
#include <stdio.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define BILLION 1000000000L
#define RSA_MOD_COUNT 3

int main(void){


    int				ret = 0;
	RSA				*r = NULL;
	BIGNUM			*bne = NULL;
	
    uint32_t RSA_MOD_SIZE [RSA_MOD_COUNT] = {1024,2048,4096};

    double diff;
    struct timespec start, end;

	unsigned long	e = RSA_F4;

    bne = BN_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){
		BN_free(bne);
        return 1;
	}

    for(int i=0; i<RSA_MOD_COUNT; i++){
        
        printf("Generating: %d bits RSA key\n", RSA_MOD_SIZE[i]);
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        r = RSA_new();
	    ret = RSA_generate_key_ex(r, RSA_MOD_SIZE[i] , bne, NULL);
	    if(ret != 1){
		    RSA_free(r);
	        BN_free(bne);
            return 1;
	    }
        clock_gettime(CLOCK_MONOTONIC, &end); 

        diff = (end.tv_sec - start.tv_sec) + (double) (end.tv_nsec - start.tv_nsec) / (double)BILLION; 
        printf("elapsed time = %lf seconds\n\n", diff);

        if(i == RSA_MOD_COUNT-1) continue;
        RSA_free(r);
    }

    printf("SUCCESS\n");


	RSA_free(r);
	BN_free(bne);

    return 0;
}
