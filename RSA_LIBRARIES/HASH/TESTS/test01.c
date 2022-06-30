/*
---------------------------------------------------------------------------------------------------------------
 Filename: test02.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 05.05.2022
 Version: 1.1
 Description: Test generate hash for SHA-1, SHA-256, SHA-512 with input strings NULL and "abc" .

 ---------------------------------------------------------------------------------------------------------------
*/

#include <stdio.h>
#include <string.h>

#include "../EXTENSIONS/ext_sha.h"


int main(){

    uint8_t hash[SHA512_BLOCK_SIZE];
    
    printf("TEST FOR NULL STRING INPUT\n-------------------------------------------------------------------------------------------------------------------------\n");

    SHA1((unsigned char*)"",0,hash);               /* SHA-1 TEST */
    printf("SHA-1: ");
    for(int i=0;i<SHA1_BLOCK_SIZE;i++)
      printf("%02X ",hash[i]);
    printf("\n\n");

    SHA256((unsigned char*)"",0,hash);         /* SHA-256 TEST */
    printf("SHA-256: ");
    for(int i=0;i<SHA256_BLOCK_SIZE;i++)
      printf("%02X ",hash[i]);
    printf("\n\n");

    SHA512((unsigned char*)"",0,hash);          /* SHA-512 TEST */
    printf("SHA-512: ");
    for(int i=0;i<SHA512_BLOCK_SIZE;i++)
      printf("%02X ",hash[i]);
    printf("\n\n\n\n");

     printf("TEST FOR STRING INPUT: abc\n-------------------------------------------------------------------------------------------------------------------------\n");

    memset(hash,0x00,SHA512_BLOCK_SIZE);         /* Set all elements im hash field to 0 */
    unsigned char message[]="abc";
    uint8_t len = strlen((char*)message);

    SHA1(message,len,hash);                /* SHA-1 TEST */
    printf("SHA-1: ");
    for(int i=0;i<SHA1_BLOCK_SIZE;i++)
      printf("%02X ",hash[i]);
    printf("\n\n");

    SHA256(message,len,hash);               /* SHA-256 TEST */
    printf("SHA-256: ");
    for(int i=0;i<SHA256_BLOCK_SIZE;i++)
      printf("%02X ",hash[i]);
    printf("\n\n");
 
    SHA512(message,len,hash);                 /* SHA-512 TEST */
    printf("SHA-512: ");
    for(int i=0;i<SHA512_BLOCK_SIZE;i++)
      printf("%02X ",hash[i]);
    printf("\n");
    return 0;
}