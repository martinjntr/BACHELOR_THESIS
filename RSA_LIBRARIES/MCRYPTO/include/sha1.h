/*
---------------------------------------------------------------------------
 Filename: sha1.h
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 20.05.2022
 Version: 1.0

 Changes [MJ]: - Every unsigned long variable was changed to uint32_t for 
              using on 64-bit operating system
---------------------------------------------------------------------------
*/

/* sha1.h */

#ifndef _SHA1_H
#define _SHA1_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct {
    uint32_t state[5];  //MJ change unsigned long -> uint32_t
    uint32_t count[2];  //MJ change unsigned long -> uint32_t
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Init(SHA1_CTX* context);
void SHA1Update(SHA1_CTX* context, unsigned char* data, unsigned int len);
void SHA1Final(unsigned char digest[20], SHA1_CTX* context);

#ifdef __cplusplus
}
#endif

#endif


