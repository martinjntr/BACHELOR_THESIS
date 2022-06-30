/*
---------------------------------------------------------------------------
 Filename: mcrypto.h
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 20.05.2022
 Version: 1.0

 Changes [MJ tag]: -  On line 34 adding directive for choosing number 
					  generator
---------------------------------------------------------------------------
*/

/* libmcrypto - math crypto library - header file */
#ifndef _MCRYPTO_H_
#define _MCRYPTO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* data type macros */
#define UINT 	unsigned int
#define BYTE	unsigned char
#define DWORD 	uint32_t

/* define all return codes here */

/* some C preprocessors to customize the lib operation */
#define STRONG_RANDOM	1	/* use cryptographic prng rather than rand() function */

#ifdef __linux__ //MJ platform independent
	#define LINUX_URANDOM	1	/* use linux's /dev/urandom for cryptographic prng */
#elif defined _WIN32
	#define LINUX_URANDOM	0
#endif

#define N_TEST_PRIME 200	/* The number of rounds for Miller-Rabin primality test */

int prng(BYTE* buf, int buf_size);
	/* generate pseudo-random numbers using linux's /dev/urandom */

void mcrypto_msg(const char *s);
	/* enable MCRYPTO_DEBUG to dump simple debug message to stdout */

void mcrypto_dump(char *desc, BYTE *p, UINT len);
	/* more detail debug information */

#ifdef __cplusplus
}
#endif

#endif
