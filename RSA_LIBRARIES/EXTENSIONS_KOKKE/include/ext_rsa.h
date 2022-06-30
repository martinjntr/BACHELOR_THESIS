/*
---------------------------------------------------------------------------------------------------------------
 Filename: ext_rsa.h
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 05.05.2022
 Version: 1.1
 Description: Header file contains declaration of function for RSA encrypt and decrypt
              with OAEP padding or NON padding.
              Also contains declaration of functions for convertion MSG to BN or BN to MSG
              Defines types of RSA key, RSA public key, RSA private key.

 ---------------------------------------------------------------------------------------------------------------
*/


#ifndef _EXT_RSA_H
 #define _EXT_RSA_H

 #include "../../KOKKE/bn.h"
 #include "../../OAEP/oaep.h"
 

 #define OAEP_PKCS1_PADDING 1
 #define NONE_PADDING 0 

 typedef struct{
     struct bn d;   /* Private exponent */
     struct bn n;   /* Modulus RSA */
 }RSA_PRIVATE_KEY;

typedef struct{
    struct bn e;    /* Public exponent */
    struct bn n;    /* Modulus RSA */
}RSA_PUBLIC_KEY;

typedef struct{
 RSA_PUBLIC_KEY pub;    /* Public key */
 RSA_PRIVATE_KEY priv;  /* Private key */
}RSA_KEY;

typedef enum{
  PUBLIC,
  PRIVATE
}TYPE_KEY;

/*
RSA_KEY_INIT: function initialize static array for storing RSA keys, set all members to 0
Arguments: 
          key: pointer to which key will be initialized
*/
void RSA_KEY_INIT(RSA_KEY* key);

/*
print_BN: function print BN number in HEX format
Arguments:
          a: BN format where is stored number
*/
void print_BN(struct bn* a);

/*
RSA_encrypt: function encrypt plaintext using RSA key pair and result stores into preallocated memory place
Arguments:
         message: plaintext message
         mlen: size of message in bytes
         encrypted: preallocated place where will be stored ciphertext of RSA_MOD_SIZE_BYTES
         key: RSA public key pair (e,n)
         len_rsa: size of RSA modulus in bites
         padding: using OAEP padding [https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf] or none padding
Returns size of ciphertext in bytes
Returns on error:
        -1: message too long
        -2: memory allocation problem
        -3: unable to obtain random bytes
        -4: bad padding option
*/
int RSA_ENCRYPT(uint8_t* message, uint32_t mlen, uint8_t* encrypted, RSA_PUBLIC_KEY* key, uint32_t len_rsa, int padding);

/*
RSA_decrypt: function decrypt ciphertext using RSA key pair and result stores into preallocated memory place
Arguments:
         message: ciphertext message
         mlen: length of message in bytes it is result of function RSA_ENCRYPT
         key: RSA private key pair (d,n)
         result: preallocated place where will be stored result of decoding
         padding: using OAEP padding [https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf] or none padding
Returns size of plaintext which is store in decrypted memory in bytes
Returns on error:
        -1: message to long
        -2: memory allocation problem
        -4: bad padding option
        -5: decoding or decryption error
*/
int RSA_DECRYPT(uint8_t* message, RSA_PRIVATE_KEY* key, uint8_t* result,uint32_t len_rsa, int padding);

/*
MSG2_BN: function converts message of mlen length to BN format
Arguments: 
          message: message which will be converted
          mlen: length of message in bytes
          a: BN format for storing result
Returns 0 if success
Returns -1 if message is long [message > BN_ARRAY_SIZE*WORD_SIZE]
*/
int MSG2_BN(uint8_t* message, uint32_t mlen, struct bn* a);

/*
BN2_MSG: function convert BN number to uint8_t format
Arguments: 
          a: BN which will be converted to uint8_t array
          message: result for storing uint8_t array, array will be automatically preallocated
          padding: OAEP or NONE padding options are available
Returns length of message
*/
int BN2_MSG(struct bn* a, uint8_t* message,int padding);

#endif