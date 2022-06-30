/*
---------------------------------------------------------------------------
 Filename: bignum.h
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 20.05.2022
 Version: 1.0

 Changes [MJ tag]: -  Adding preporcessor directives for choosing BASE 
					  system
---------------------------------------------------------------------------
*/

/*
 * Filename:      bignum.h
 * Author:        Junwei Wang(wakemecn@gmail.com)
 * Last Modified: 2014-06-18 17:56
 * Description:
 *
 */

#ifndef __BIGNUM_H__
#define __BIGNUM_H__

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
	- MJ adding preprocessor directive for choosing
	  size of BASE compilation
	- BN number consist of more small number with
	  one common base
	- E donotes length of BASE variable in bits
	- B denotes MAX value for storing number in 
	  one 
	- Example: Representation number 123 with 
	  base 10 can be viewed as x[0] = 3, x[1] = 2,
	  x[2] = 1 for BN number X
*/
#ifdef BIT32 
// -------- 32 bit number system -----------
typedef __int128_t block;
typedef unsigned int var; /* Real value stored in bignumber format */

#define B 4294967296   
#define E 32          // B = 2^E, E = 1, 2, 3, ..., 32
#define MASK 0xffffffff
#define HITMASK 0x01000000 /* Use for chcek if modulus has right size, avoiding m > n */


#elif defined BIT8
// -------- 8 bit number system ---------------
typedef int64_t block;
typedef unsigned char var;

#define B 256
#define E 8
#define MASK 0xff
#define HITMASK 0x01

#endif


// MJ Unusable
//typedef int64_t block;
/* B is the base of the bignum system, it has to be an exponention 2 */
/*#define B 16777216
#define E 24       // B = 2^E, E = 1, 2, ..., 31
#define MASK 0xffffff
*/

/*
#define B 16 
#define E 4       // B = 2^E, E = 1, 2, 3, ..., 32
#define MASK 0xf
*/

// for miller-rabin tester-rabin tester-rabin tester-rabin test
#define TEST_CNT 80

typedef struct {
	int sign;
	int size;
	block *tab;
} bignum;

bignum str2bignum(char * str);
bignum add(bignum a, bignum b);
bignum sub(bignum a, bignum b);
bignum mult(bignum a, bignum b);
bignum reminder(bignum a, bignum n);

bignum addmod(bignum a, bignum b, bignum n);
bignum multmod(bignum a, bignum b, bignum n);
bignum expmod(bignum a, bignum b, bignum n);

int millerrabin(bignum a, int t);
bignum genrandom(int len);
bignum genrandomprime(int len);

// other functions
bignum digit2bignum(int d);

int iszero(bignum a);
int isone(bignum a);
int length(bignum a);
int isnormalized(bignum a);
int compare(bignum a, bignum b);

bignum leftshift(bignum a, int k);
bignum rightshift(bignum a, int k);

void copy(bignum *dest, bignum src);
void printbignum(bignum a);

bignum inverse(bignum a, bignum n);
bignum gcd(bignum a, bignum b);
bignum divi(bignum a, bignum n);
bignum * normalized_divi(bignum a, bignum b);

#endif
