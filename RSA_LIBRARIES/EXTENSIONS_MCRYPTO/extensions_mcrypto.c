/*
---------------------------------------------------------------------------
 Filename: extensions_mcrypto.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 20.05.2022
 Version: 1.0

Description: - File contains algorithms for writing RSA key
				to FILE format
			 - Reading and writing message to FILE

---------------------------------------------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "extensions_mcrypto.h"

int WRITE_RSA_KEY_FILE(const char* filename_private_key, const char* filename_public_key,PKCS1_RSA_KEY* key){
    if(key == NULL){
        printf("RSA key in unknown\n");
        return -3;
    }

	// Open file for public key
    FILE* fp_public = fopen(filename_public_key,"w"); 
    if(fp_public == NULL) {
      printf("Failed to open %s\n", filename_public_key);  
      return -1;
    }

	// Open file for private key
    FILE* fp_private = fopen(filename_private_key,"w");
    if(fp_private == NULL){
        printf("Failed to open %s\n", filename_private_key);
        fclose(fp_public);
        return -2;  
    }

	// Encoding public modulus n to base64 format and store result to s_mod
    char* s_mod = mpBase64Encode(key->public_key.modulus, key->public_key.len);

	// Encoding public exponent e to base64 format and store result to s_e
    char* s_e = mpBase64Encode(key->public_key.exponent, key->public_key.len);


	/* 
		Write to FILE (PUBLIC KEY)
		1. Specific start message format
		2. Length of modulus
		3. modulus n
		4. exponent e
		5. Specific end message format
	
	*/
    fprintf(fp_public, "----------------BEGIN PKCS#1 PUBLIC KEY-------------------\n");
	fprintf(fp_public, "%d\n", key->public_key.len);
	fprintf(fp_public, "%s\n", s_mod);
	fprintf(fp_public, "%s\n", s_e);
	fprintf(fp_public, "---------------END OF PKCS#1 PUBLIC KEY-------------------\n");
    fclose(fp_public);

	// Encoding private exponent d to base64 format and store result to s_d
    char* s_d = mpBase64Encode(key->private_key.exponent, key->private_key.len);

	/* 
		Write to FILE (PRIVATE KEY)
		1. Specific start message format
		2. Length of private exponent
		3. modulus n
		4. exponent e
		5. private d exponent
		6. Specific end message format
	
	*/
    fprintf(fp_private, "----------------BEGIN PKCS#1 SECRET KEY-------------------\n");
	fprintf(fp_private, "%d\n", key->private_key.len);
	fprintf(fp_private, "%s\n", s_mod);
	fprintf(fp_private, "%s\n", s_e);
	fprintf(fp_private, "%s\n", s_d);
	fprintf(fp_private, "---------------END OF PKCS#1 SECRET KEY-------------------\n");
	fclose(fp_private);

    free(s_mod);
	free(s_e);
	free(s_d);

    return ERR_OK;
}

int WriteMsg(const char* filename, DIGIT_T message [], int mlen){
    
	// Open file for writing
	FILE* fp = fopen(filename,"w+");
    if(fp == NULL) {
      printf("Failed to open %s\n", filename);  
      return -1;
    }

	// Encode message to base64 encoding format
    char* msg = mpBase64Encode(message, mlen);

	/* 
		Write message to FILE 
		1. Specific start message format
		2. Length of message
		3. message
		4. Specific end message format
	
	*/
    fprintf(fp, "----------------BEGIN MSG-------------------\n");
	fprintf(fp, "%d\n", mlen);
	fprintf(fp, "%s\n", msg);
	fprintf(fp, "---------------END OF MSG-------------------\n");
    fclose(fp);

    return ERR_OK;
}

int LoadMsg(const char* filename, DIGIT_T* res){
   
	/* Loading 4 Lines, 1 Line cas consist of maximum
	   PKCS1_MAX_LINE_LEN characters
	*/

	char s[4][PKCS1_MAX_LINE_LEN];	
	FILE *f;
	UINT i;
	UINT len;
    UINT mlen;
	
	// Open file for reading
	f = fopen(filename, "r");
	if(f == NULL)
		return -1;
	
	memset(s, 0x00, PKCS1_MAX_LINE_LEN*4);	
	/* reading data */
	for(i=0;i<4;i++)
	{
		if(feof(f))
		{
			fclose(f);
			return -1;
		}

		// Read one line from file
		fgets(s[i], PKCS1_MAX_LINE_LEN, f);
		
		/* ignore newline charater */		
		s[i][strlen(s[i])-1] = '\0';
	}
	fclose(f);
	
	/* Decoding data */
	mlen = (UINT)atoi(s[1]);
	DIGIT_T* msg;

	// Decoding message
	if((msg = mpBase64Decode(&len, s[2]))==NULL)
		return -1; 

	// Assign message to output variable
    for(int i=0; i<len;i++){
        res[MAX_DIG_LEN-1-i] = msg[i];
    }

	// Return length of message
	return mlen;
}