/*
---------------------------------------------------------------------------------------------------------------
 Filename: ext_rsa.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 05.05.2022
 Version: 1.2
 Description: Source code contains function for RSA encrypt and decrypt with OAEP padding or NON padding.
              Also contains functions for convertion MSG to BN or BN to MSG.
 ---------------------------------------------------------------------------------------------------------------
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ext_rsa.h"


void RSA_KEY_INIT(RSA_KEY* key){ /* Set all members RSA key to 0 */
    bignum_init(&key->pub.e);
    bignum_init(&key->pub.n);
    bignum_init(&key->priv.d);
    bignum_init(&key->priv.n);
}

void print_BN(struct bn* a)
{
    int len = BN_ARRAY_SIZE; /* Length of BN number */
    while(a->array[--len] ==0);/* Ignore 0 at beginning */

    for(int i=len; i>=0; i--) printf("%08X ",a->array[i]);
    printf("\n");
}



int RSA_ENCRYPT(uint8_t * message, uint32_t mlen, uint8_t* encrypted, RSA_PUBLIC_KEY* key, uint32_t len_rsa, int padding)
{
    uint32_t len_rsa_bytes = len_rsa /8; /* Size of RSA modulus in bytes */
    struct bn m, enc;
    int err;

    uint8_t temporary[BN_ARRAY_SIZE*WORD_SIZE];
    memset(temporary,0x00,BN_ARRAY_SIZE*WORD_SIZE);

    int len = BN2_MSG(&key->n,temporary,NONE_PADDING);
    if(len < mlen) /* Check if modulus > message length */
        return -1;

    bignum_init(&m); /* Set init value 0 to variable*/
    bignum_init(&enc);
    memset(encrypted,0x00,len_rsa_bytes);
  
    if(padding == OAEP_PKCS1_PADDING){
        HASH_FUNCTION hash = SHA1_FUNC; /* we can use SHA1, SHA256 and SHA512 hash function */
        uint8_t EM_OAEP[len_rsa_bytes]; 
        err=  oaep_encode(message,mlen,len_rsa_bytes,NONE,EM_OAEP,hash); /* Calculate OAEP padding for RSA */
        if(err <0) return err;

        err = MSG2_BN(EM_OAEP,len_rsa_bytes,&m); /* Convert uint8_t array to BN format */
        if(err <0) return err;
    }

    else if(padding == NONE_PADDING){
        err = MSG2_BN(message,mlen,&m);
        if(err <0) return err;
    }

    else return -4;

    pow_mod_faster(&m,&key->e,&key->n,&enc); /* Calculate m^e mod n*/

    int res = BN2_MSG(&enc,encrypted,NONE_PADDING); /* convert BN format to uint8_t array */
    return res;
}

int RSA_DECRYPT(uint8_t* message, RSA_PRIVATE_KEY* key, uint8_t* result,uint32_t len_rsa, int padding)
{
    uint32_t len_rsa_bytes = len_rsa /8;
    struct bn c, res;
    int err;

    bignum_init(&c); /* Set init value 0 to variable */
    bignum_init(&res);
    memset(result,0x00,len_rsa_bytes);

    err = MSG2_BN(message,len_rsa/8,&c); /* Convertion message to BN format */
    if(err < 0) return err;

    pow_mod_faster(&c,&key->d,&key->n,&res); /* Calculate c^d mod n */

    int count;
    if(padding == OAEP_PKCS1_PADDING){

        HASH_FUNCTION hash = SHA1_FUNC; /* we can use SHA1, SHA256 and SHA512 hash function */
        uint8_t decoded[len_rsa_bytes];

        count = BN2_MSG(&res,decoded,OAEP_PKCS1_PADDING); /* Convert BN to message */
        if(count <0) return count;

        count =  oaep_decode(decoded,len_rsa/8,NONE,hash,decoded); /* Calculate OAEP decoding */
        if(count <0) return count;

        for(int i=0;i<count;i++)  /* Asign data to result variable */
            result[i] = decoded[i];    
    }
      
    else if(padding == NONE_PADDING)
        count = BN2_MSG(&res,result,NONE_PADDING); /* Convert BN to message */
    
    else return -4;
    
    return count;
}



int MSG2_BN(uint8_t* message, uint32_t mlen, struct bn* a){

    if(mlen > BN_ARRAY_SIZE*WORD_SIZE) return -1; /* Check if m > n in RSA system */
    uint8_t reverse[mlen];
    memset(reverse,0x00,mlen);

    while(message[mlen-1] == 0) --mlen; /* Set mlen value to size without 0 at the end */

    for(int i =0;i<mlen;i++) reverse[i] = message[mlen-1-i]; /* Reverese message */
    bignum_init(a);
    memcpy(a->array,reverse,mlen); /* Copy reversed message to BN array */

    return 0;
}

int BN2_MSG(struct bn* a, uint8_t* message,int padding){
   
    uint8_t* ptr =  (uint8_t*)(a->array); /* Set pointer to BN array */
    ptr+= (BN_ARRAY_SIZE * WORD_SIZE) -1; /* Last byte in BN array */
    int count =0;
 
    while(*ptr == 0){ /* Count 0 in BN number at the end */
        count++;
        ptr--;
    }


    count = BN_ARRAY_SIZE * WORD_SIZE - count; /* Length of MSG in bytes */
    if(padding == OAEP_PKCS1_PADDING){ /* for 0x00 at the beginning */
      ptr++;
      count++;
    }
   
    for(int i=0;i<count;i++) message[i] = *(ptr--); /* Copy data to result variable */
    return count;
 }