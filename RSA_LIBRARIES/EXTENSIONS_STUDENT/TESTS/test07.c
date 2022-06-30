/*
---------------------------------------------------------------------------------------------------------------
 Filename: test07.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 05.06.2022
 Version: 1.2
 Description: Test generate RSA key pair[1024 bit] and write Public and Private key to file.

 ---------------------------------------------------------------------------------------------------------------
*/

#include <stdio.h>
#include "../include/ext_rsa.h"
#include "../include/ext_file.h"

#define RSA_MOD_SIZE 1024 /* Size of RSA modulus in bits */
#define GAP 16  /* Number of elements per line in file, when writing to file */

int main(int argc, char** argv){

  if(argc != 3){
      printf("Add filename for storing rsa key 1.Public key 2.Private key Using: test04 public_key private_key\n");
      return 1;
  }

  int err;
  rsa_key key;
  err= key_gen(&key,RSA_MOD_SIZE); /* Generate RSA key pair[public, private] length of RSA_MOD_SIZE  */
  if(err != 0){
    printf("Error occurs: RSA key generate\n");
    return 1;
  }

  /* Write RSA public key to file with size of GAP elements per line, function write to file [e,n]-> RSA public key */
  err= WriteRSA_Key(argv[1],&key,GAP,PUBLIC_KEY);
  if(err != 0){
    printf("Error occurs: Write RSA Public key to file\n");
    RSA_key_free(&key);
    return 1;
  }

  /* Write RSA private key to file with size of GAP elements per line, function write to file [d,n]-> RSA private key */
  err = WriteRSA_Key(argv[2],&key,GAP,PRIVATE_KEY);
  if(err != 0){
    printf("Error occurs: Write RSA Private key to file\n");
    RSA_key_free(&key);
    return 1;
  }

  RSA_key_free(&key); /* Destroy RSA key memory */
    
  printf("SUCCESS\n");

  return 0;
}