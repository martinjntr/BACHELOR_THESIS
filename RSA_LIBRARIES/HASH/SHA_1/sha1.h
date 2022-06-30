/*
---------------------------------------------------------------------------
 Filename: sha1.h
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 20.05.2022
 Version: 1.0

 Changes [MJ tag]: -  Change variable WORD to ONE_WORD, duplicity with
						Winlibs GCC compilier
---------------------------------------------------------------------------
*/

/*********************************************************************
* Filename:   sha1.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef SHA1_H
#define SHA1_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA1_BLOCK_SIZE 20              // SHA1 outputs a 20 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte

// MJ WORD -> ONE_WORD
typedef unsigned int  ONE_WORD;   // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	ONE_WORD datalen; // MJ WORD -> ONE_WORD
	unsigned long long bitlen;
	ONE_WORD state[5]; // MJ WORD -> ONE_WORD
	ONE_WORD k[4]; // MJ WORD -> ONE_WORD
} SHA1_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const BYTE data[], size_t len);
void sha1_final(SHA1_CTX *ctx, BYTE hash[]);

#endif   // SHA1_H
