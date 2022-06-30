/*
---------------------------------------------------------------------------
 Filename: ext_bignum.h
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 11.05.2022
 Version: 1.2
 Description: Header file contains declaration of functions fo print, 
              convertion bignum to other format and generate 
              cryptographical secure random number.
---------------------------------------------------------------------------
*/


#ifndef __EXT_BIGNUM_H__
 #define __EXT_BIGNUM_H__
 #include "../../STUDENT/src/bignum.h"

/*
print_bignum: function print bignum in hex format
Arguments:
          a: bignum which will be printed 
*/
void print_bignum(bignum a); 

/*
 msg2bignum: function converts message to bignum format
 Arguments: 
          msg: message 
          length: length of message
Returns bignum format with converted message
*/
bignum msg2bignum(var* msg, int length);

/*
bignum2msg: function converts bignum format to message
Arguments:
          a: bignum which contains message
          data: converted message from bignum
          len: length of data memory allocation space, 
               if len > bignum.size bignum will be written to data with
               zero-padding at the beggining
Returns length message if success
Returns: -1 if data = NULL
         -2 if bignum size > len
*/
int bignum2msg(bignum a,var* data, int len);

/*
generate_secure_random: function generate random number
Arguments:
        length: sizeof generates number in bits
Returns bignum which storage random number 
*/
bignum generate_secure_random(int length);

/*
generate_secure_randomprime: function generate cryptographically secure 
random number
Arguments: 
         length: sizeof generates number in bits
Returns bignum which storage cryptographically secure random number
*/
bignum generate_secure_randomprime(int length);

/*
reverse_4bytes: function converts every 4 bytes recursively, for 
example [0][1][2][3][4][5][6][7] byets will we [3][2][1][0][7][6][5][4]
Arguments: 
         message: data which every 4 bytes will be set recursively
         len: length of message in bytes
*/
void reverse_4bytes(uint8_t* message, int len);

#endif