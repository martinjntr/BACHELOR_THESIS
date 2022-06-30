/*
---------------------------------------------------------------------------------------------------------------
 Filename: ext_file.h
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 06.03.2022
 Version: 1.1
 Description: Header file contains declaration functions for reading and writing message, public and private keys
              to file format.
              Defines types of messages for specific writing to file format [RSA KEY, MESSAGE] 
 ---------------------------------------------------------------------------------------------------------------
*/

#ifndef _EXT_FILE_H
  #define _EXT_FILE_H

#include <stdint.h>
#include "ext_rsa.h"

#define FILE_LEN 80
#define FILE_LINE_LEN 100

#define HEX_FORMAT 16

 /* Messages for file format saving*/
static const unsigned char bmsg [] = "-----BEGIN MSG----";
static const unsigned char emsg [] = "-----END MSG-----";
static const unsigned char bpk [] = "-----BEGIN PRIVATE KEY-----";
static const unsigned char epk [] = "-----END PRIVATE KEY-----";
static const unsigned char bpubk [] = "-----BEGIN PUBLIC KEY-----";
static const unsigned char epubk [] = "-----END PUBLIC KEY-----";


/*
WR_FILE: function write numbers of len size to fp descriptor
Arguments:
         fp: file descriptor where numbers will be storaged
         data: field of numbers
         len: length of numbers
         width: sizeof numbers per line in file
*/
void WR_FILE(FILE* fp, uint8_t* data, int len, int width);

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
int Write_MSG_FILE(const char* filename, uint8_t* data, int len, int width);

/*
Read_MSG_FILE: function read message from file
Arguments:
         filename: name of the file from which we will read message
         data: double pointer where to stoarage message, this function automatically allocate memory storage 
Returns length of message on success
Returns on error:
                -1: file opening problem occurs
                -2: wrong type file reading
                -3: memory allocation problem
*/
int Read_MSG_FILE(const char* filename,uint8_t** data);


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
                -5: number in FILE is bigger than modulus 

*/
int ReadRSA_KEY(const char* filename,RSA_KEY* key,TYPE_KEY type);


/*
READ_BLOCK: function reads one number from FILE and store to [a] 
            variable which is bignum format
Arguments:
         fp: pointer to file, file must be open 
         target: when target string is read, reading will be stopped
         a: variable for storing result
Returns 0 on success
Returns on error: 
                -4: memory allocation problem
                -5: number in FILE is bigger than modulus  
*/
int READ_BLOCK(FILE* fp,const char* target, struct bn* a);

#endif