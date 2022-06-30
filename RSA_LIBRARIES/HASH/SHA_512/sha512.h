/*
---------------------------------------------------------------------------
 Filename: sha512.h
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 20.05.2022
 Version: 1.0

 Changes [MJ tag]: -  sha512 to SHA512 for good-looking method with other 
                      SHA implementations
---------------------------------------------------------------------------
*/

#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>

#include "fixedint.h"

/* state */
typedef struct sha512_context_ {
    uint64_t  length, state[8];
    size_t curlen;
    unsigned char buf[128];
} sha512_context;


int sha512_init(sha512_context * md);
int sha512_final(sha512_context * md, unsigned char *out);
int sha512_update(sha512_context * md, const unsigned char *in, size_t inlen);

//MJ sha512 -> SHA512
int SHA512(const unsigned char *message, size_t message_len, unsigned char *out);

#endif
