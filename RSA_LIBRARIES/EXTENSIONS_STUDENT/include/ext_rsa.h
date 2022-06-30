/*
---------------------------------------------------------------------------
 Filename: ext_rsa.h
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 11.05.2022
 Version: 1.2
 Description: Header file contains declaration of function for RSA key 
              genrate, encrypt and decrypt with OAEP padding or NON padding.
              Also contains declaration of function for destory allocation 
              memory for RSA key pair.Defines types of RSA key, RSA public 
              key, RSA private key.Defines types of messages for specific 
              writing to file format [RSA KEY, MESSAGE] 
---------------------------------------------------------------------------
*/

#ifndef EXT_RSA_H
  #define EXT_RSA_H

#include "ext_bignum.h"
#include "../../OAEP/oaep.h"
#include "../../HASH/EXTENSIONS/ext_sha.h"


#define OAEP_PKCS1_PADDING 1
#define NONE_PADDING 0

typedef struct{
 bignum n;                  /* Modulus RSA */
 bignum d;                  /* Private exponent */
}rsa_private_key; 

typedef struct{
 bignum n;                  /* Modulus RSA */
 bignum e;                  /* Public exponent */
}rsa_public_key; 

typedef struct{
   rsa_public_key pub;       /* Public key */
   rsa_private_key priv;     /* Private key */
}rsa_key; 


 /* Messages for file format saving*/
static const unsigned char bmsg [] = "-----BEGIN MSG-----";
static const unsigned char emsg [] = "-----END MSG-----";
static const unsigned char bpk [] = "-----BEGIN PRIVATE KEY-----";
static const unsigned char epk [] = "-----END PRIVATE KEY-----";
static const unsigned char bpubk [] = "-----BEGIN PUBLIC KEY-----";
static const unsigned char epubk [] = "-----END PUBLIC KEY-----";

/*
key_gen: function generate RSA key pairs of size length and store into 
         rsa_key struct variable
Arguments:
   rsa_key: pointer to rsa_key structure where the RSA key will be stored
   lenght: size of modulus RSA crypto system in bits
Returns 0 if sucess
Returns -1 if allocation problem
 */

int key_gen(rsa_key* new_key, int length);

/*
RSA_encrypt: function encrypt plaintext using RSA key pair and result 
             stores into preallocated memory place
Arguments:
   message: plaintext message
   mlen: size of message in bytes
   key: RSA public key pair (e,n)
   encrypted: preallocated place where will be stored ciphertext of 
   RSA_MOD_SIZE_BYTES
   len: size of RSA modulus in bites
   padding: using OAEP padding or none padding
Returns size of ciphertext in bytes
Returns on error:
   -1: message too long
   -2: memory allocation problem
   -3: unable to obtain random bytes
   -4: bad padding option
*/


int RSA_encrypt(var* message,int mlen,rsa_public_key key, var* encrypted,
uint32_t len, int padding);

/*
RSA_decrypt: function decrypt ciphertext using RSA key pair and result 
             stores into preallocated memory place
Arguments:
   encrypted_message: ciphertext message
   key: RSA private key pair (d,n)
   decrypted: preallocated place where will be stored plaintext of 
              RSA_MOD_SIZE_BYTES
   padding: using OAEP padding or none padding
Returns size of plaintext which is store in decrypted memory in bytes
Returns on error:
   -2: memory allocation problem
   -3: decrypted storage allocation problem
   -4: bad padding option
   -5: decoding or decryption error
*/
int RSA_decrypt(var* encrypted_message,rsa_private_key key, var* decrypted,
uint32_t len,int padding);


/*
RSA_key_free: function destroy allocation memory for storing private and 
              public key
Arguments:
   key: pointer to RSA key
*/
void RSA_key_free(rsa_key* key);

/*
Private_key_free: function destroy allocation memery for private key
Arguments:
   key: pointer to RSA key
*/
void Private_key_free(rsa_key* key);

/*
Public_key_free: function destroy allocation memery for public key
Arguments:
   key: pointer to RSA key
*/
void Public_key_free(rsa_key* key);


#endif