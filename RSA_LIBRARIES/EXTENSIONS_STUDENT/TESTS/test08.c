/*
---------------------------------------------------------------------------------------------------------------
 Filename: test08.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 05.06.2022
 Version: 1.3
 Description: Test read message, private key, public key from file [1024 bit]. Encrypt and decrypt message using private and
              public key with OAEP PKCS#1 padding.

 ---------------------------------------------------------------------------------------------------------------
*/

#include <stdio.h>
#include "../include/ext_rsa.h"
#include "../include/ext_file.h"


int main(int argc, char** argv){

    if(argc != 4){
        printf("Add filename: 1.-> message file 2.-> public key 3.private key Using: test06 message public_key private_key\n");
        return 1;
    }

    int res, err, mlen;

    #ifdef BIT8
        uint8_t* message; /* Pointer where message will be stored */
    #elif defined BIT32
        uint32_t* message;
    #endif

    /*Reading message from file and store to address of pointer message, 
     message pointer will contain message of mlen length, function return length of message */
    mlen = Read_MSG_FILE(argv[1],&message);
    if(mlen <= 0){
        printf("Error occurs: reading message from file\n");
        return 1;
    }

    rsa_key key;

    err = ReadRSA_Key(argv[2],&key,PUBLIC_KEY); /* Reading public key from file and storing to key pointer */
    if(err != 0){
        printf("Error occurs: reading RSA public key\n");
        free(message);
        return 1;
    }

    err = ReadRSA_Key(argv[3],&key,PRIVATE_KEY); /* Reading private key from file and storing to key pointer */
     if(err != 0){
        printf("Error occurs: reading RSA public key\n");
        free(message);
        Public_key_free(&key);
        return 1;
    }

    if(key.priv.n.size != key.pub.n.size){ /* Check if modulus have same lenght for both keys */
        printf("Error occurs: Keys dont have same size\n");
        RSA_key_free(&key);
        free(message);
        return 1;
    }
    

    /* Memory for storing results and  */
    #ifdef BIT8
        /* RSA modulus size in bits */
        uint32_t RSA_MOD_SIZE = key.pub.n.size * 8; 
        /* Maximum length of message, it is for when SHA1 hash function is used */
        uint32_t max_msg_len =  key.pub.n.size - 2*SHA1_BLOCK_SIZE -1; 

        uint8_t enc[RSA_MOD_SIZE/8];
        uint8_t dec[RSA_MOD_SIZE/8];

    #elif defined BIT32
         /* RSA modulus size in bits */
        uint32_t RSA_MOD_SIZE = (key.pub.n.size * 8) * sizeof(var);
        /* Maximum length of message, it is for when SHA1 hash function is used */
        uint32_t max_msg_len =  key.pub.n.size - (2*SHA1_BLOCK_SIZE -1)/sizeof(var); 

        uint32_t enc[RSA_MOD_SIZE/32];
        uint32_t dec[RSA_MOD_SIZE/32];

    #endif

    
    if(mlen > max_msg_len){
        printf("Error occurs: Messsage is too long \n");
        RSA_key_free(&key);
        free(message);
        return 1;
    }

    /* Encrypt message of mlen length and store result to enc, RSA encryption with OAEP PKCS1 PADDING */
    err = RSA_encrypt(message,mlen,key.pub,enc,RSA_MOD_SIZE,OAEP_PKCS1_PADDING);
    
    
    if(err <=0){
        printf("Error occurs: RSA encrypt problem\n");
        free(message);
        RSA_key_free(&key);
        return 1;
    }
    
     /* Decrypt message stored in enc and store result to dec, 
        RSA decryption with OAEP PKCS1 PADDING, function return length of message */
    res = RSA_decrypt(enc,key.priv,dec,RSA_MOD_SIZE,OAEP_PKCS1_PADDING);
    
    if(res < 0 || (res != mlen)){ /* Check for result if original message has same lenght as decrypted */
        printf("Error occurs: RSA decrypt problem\n");
        free(message);
        RSA_key_free(&key);
        return 1;
    }

    for(int i=0;i<res;i++){ /* Check if original message members are same as decrypted members */
        if(dec[i] != message[i]){
            printf("Error occurs: message and result comparation problem\n");
            free(message);
            RSA_key_free(&key);
            return 1;
        }
    }

    free(message);
    RSA_key_free(&key); /* Destroy public and private key */
    printf("SUCCESS\n");

    return 0;
}