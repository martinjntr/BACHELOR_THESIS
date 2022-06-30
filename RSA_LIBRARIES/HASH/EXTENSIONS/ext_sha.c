/*
---------------------------------------------------------------------------------------------------------------
 Filename: ext_sha.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 05.05.2022
 Version: 1.1
 Description: Source code contains function for compute SHA-1 and SHA-256 hash.
 ---------------------------------------------------------------------------------------------------------------
*/

#include "ext_sha.h"


void SHA1(unsigned char* data, unsigned int DATAlen, unsigned char* hash) 
{
    SHA1_CTX shactx;
    sha1_init(&shactx);
    sha1_update(&shactx,data, DATAlen);
    sha1_final(&shactx, hash);   
}

void SHA256(unsigned char* data, unsigned int data_len, unsigned char* hash)
{
 SHA256_CTX shactx;
 sha256_init(&shactx);
 sha256_update(&shactx,data,data_len);
 sha256_final(&shactx,hash);
}
