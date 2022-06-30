/*
---------------------------------------------------------------------------
 Filename: extensions_mcrypto.h
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 20.05.2022
 Version: 1.0

Description: - Connect RSA public and private key to one structure format
                PKCS1_RSA_KEY
             - Adding function for storing and reading message from FILE 
             - Adding function for writing RSA key ro FILE

---------------------------------------------------------------------------
*/

#ifndef EXTENSIONS_BIGDIGITS_H
  #define EXTENSIONS_BIGDIGITS_H

#include "../../MCRYPTO/include/bigdigits.h"
#include "../../MCRYPTO/include/pkcs1-rsa.h"
#include "../../MCRYPTO/include/hash.h"
#include "../../MCRYPTO/include/sha1.h"
#include "../../MCRYPTO/include/sha2.h"

typedef struct {
  PKCS1_RSA_PUBLIC_KEY public_key;
  PKCS1_RSA_PRIVATE_KEY private_key;
  UINT mod_len;
}PKCS1_RSA_KEY;

/*
LoadMsg: loading message from file, message is written in file with base64
          encodig format
Arguments: 
        filename: name of file where is message stored
        res: Storage for result, array must by allocated with
             MAX_DIG_LEN size
Return length of message on success.
Returns -1: problem with file
*/
int LoadMsg(const char* filename, DIGIT_T* res);

/*
WriteMsg: writing message to file, message will be written in file 
          with base64 encodig format
Arguments: 
        filename: name of file where to write message
        message: message 
        mlen: length of message
Return macro ERR_OK if message was sucesfully wtitten
Returns -1: problem with file
*/
int WriteMsg(const char* filename, DIGIT_T message [], int mlen);

/*
WRITE_RSA_KEY_FILE: writing RSA public and private key to file
          with base64 encodig format
Arguments: 
        filename_private_key: name of file where will be stored 
                              private key
        filename_public_key: name of file where will be stored 
                              public key

Return macro ERR_OK if keys was sucessfully written
Returns on error:
        -1: problem with public key file
        -2: problem with private key file
        -3: RSA key is empty
*/
int WRITE_RSA_KEY_FILE(const char* filename_private_key, const char* filename_public_key,PKCS1_RSA_KEY* key);

#endif