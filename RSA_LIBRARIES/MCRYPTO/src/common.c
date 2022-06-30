/*
---------------------------------------------------------------------------
 Filename: common.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 20.05.2022
 Version: 1.0

 Changes [MJ tag]: -  On line 49 block of code which using rand_s(),
					  secure random number genrator
---------------------------------------------------------------------------
*/

/* common functions for libmcrypto */
#define _CRT_RAND_S //MJ add macro for number generator rand()_s

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#ifdef __linux__
	/* linux-specific include files */
	#include <unistd.h>
	#include <sys/types.h>
	#include <sys/stat.h>
#elif defined(window)
	/* window-specific include files */
#endif 

#include "mcrypto.h"

int prng(BYTE* buf, int buf_size)
{
#if LINUX_URANDOM	    	
	int fd;
    
    	if((fd = open("/dev/urandom", O_RDONLY)) < 0) {
        	perror("/dev/urandom");
        	return -1;
    	}
    	read(fd, buf, buf_size);
    	close(fd);
#else 

 	/*MJ adding secure random number generator for
	 windows */

	UINT rnd;
	errno_t err;
	
	for(int i=0;i<buf_size;i++){
		err = rand_s(&rnd);
        if (err != 0) return 1;

		buf[i] = (BYTE) rnd;
	}
#endif		
	return 0;
}

/* Useful Function for Debug */
void mcrypto_msg(const char *s)
{
#ifdef MCRYPTO_DEBUG
	fprintf(stderr, "debugging message - file %s line %d : %s", __FILE__, __LINE__, s);
#endif
}

void mcrypto_dump(char *desc, BYTE *p, UINT len)
{
#ifdef MCRYPTO_DEBUG
	UINT i = 0;
	
	printf("[%s]\n", desc);
	while (len--) {
		if ((i % 20) == 0 && i)
			printf("\n");
		fprintf(stderr, "%02x ", p[len]);
		i++;
	}
	fprintf(stderr, "\n");
#endif
}
