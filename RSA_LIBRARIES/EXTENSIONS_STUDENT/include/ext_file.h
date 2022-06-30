/*
---------------------------------------------------------------------------
 Filename: ext_file.h
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 11.05.2022
 Version: 1.3
 Description: Header file contains declaration functions for reading and 
              writing message, public and private keys to file format.
---------------------------------------------------------------------------
*/

#ifndef EXT_FILE_H
  #define EXT_FILE_H

 #include "ext_rsa.h"

typedef enum{
  PUBLIC_KEY,
  PRIVATE_KEY,
} FILE_KEY;

#define FILE_LEN 80
#define FILE_LINE_LEN 100

#define HEX_FORMAT 16


/*
WR_FILE: function write bignum number to fp descriptor with specific format
Arguments:
    fp: file descriptor where bignum number will be storaged
    data: bignum format where bignum number is storaged
    len: length of numbers which are storaged in bignum format
    width: sizeof numbers per line in file
*/
void WR_FILE(FILE* fp, bignum* data, int len, int width);

/*
Write_MSG_FILE: function write message in specific format to file
Arguments:
    filename: name of the file where message will be stored
    data: pointer to message 
    len: length of message
    width: sizeof message block which will be storaged per line in file
Returns 0 on success
Returns -1 if file opening problem occurs
*/
int Write_MSG_FILE(const char* filename, var* data, int len, int width);

/*
Read_MSG_FILE: function read message from file
Arguments:
    filename: name of the file from which we will read message
    msg: double pointer where to stoarage message, this function 
         automatically allocate memory storage 
Returns length of message on success
Returns on error:
    -1: file opening problem occurs
    -2: wrong type file reading
    -3: memory allocation problem
*/
int Read_MSG_FILE(const char* filename,var** msg);

/*
WriteRSA_key: function write RSA key pair into file in specific format
Arguments:
    filename: name of the file where will be stored RSA key pair
    key: RSA key pair which contains private, public exponent and 
         RSA modulus
    width: sizeof big number block RSA key pair per line 
    type: we can choose PRIVATE or PUBLIC key to storage into file
Returns 0 on success
Returns on error:
    -1: file opening problem occurs
    -2: wrong type FILE_KEY type assigned
*/
int WriteRSA_Key(const char* filename,rsa_key* key, int width,
FILE_KEY type);

/*
ReadRSA_Key: function reads RSA key pair from file
Arguments:
    filename: name of the file from which we will RSA key pair
    key: pointer to RSA key pair where key will be stored
    type: reading PRIVATE or PUBLIC key
Returns 0 on success
Returns on error:
    -1: file opening problem occurs
    -2: wrong type file reading
    -3: wrong type FILE_KEY type assigned
    -4: memory allocation problem

*/
int ReadRSA_Key(const char* filename, rsa_key* key,FILE_KEY type);

/*
READ_BLOCK: function reads one number from FILE and store to [a] 
            variable which is bignum format
Arguments:
    fp: pointer to file, file must be open 
    target: when target string is read, reading will be stopped
    a: variable for storing result
Returns 0 on success
Returns -4 if memory allocation problem occurs 
*/
int READ_BLOCK(FILE* fp,const char* target, bignum* a);

#endif