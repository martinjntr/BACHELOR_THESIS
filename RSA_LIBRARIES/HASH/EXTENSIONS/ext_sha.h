/*
---------------------------------------------------------------------------------------------------------------
 Filename: ext_sha.h
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 05.05.2022
 Version: 1.1
 Description: Header file contains declaration for functions SHA-1 and SHA-256 hash and SHA-512 size.

 ---------------------------------------------------------------------------------------------------------------
*/

#ifndef _EXT_SHA_H
 #define _EXT_SHA_H

 /* enumeration type for choosing hash function type*/
typedef enum
{
      SHA1_FUNC, /* SHA-1 */
      SHA256_FUNC, /* SHA-256 */
      SHA512_FUNC /* SHA-512 */
} HASH_FUNCTION;

 #include "../SHA_1/sha1.h"
 #include "../SHA_256/sha256.h"
 #include "../SHA_512/sha512.h"

  
 #define SHA512_BLOCK_SIZE 64

 void SHA1(unsigned char* data, unsigned int DATAlen, unsigned char* hash) ;
 void SHA256(unsigned char* data, unsigned int data_len, unsigned char* hash);


#endif