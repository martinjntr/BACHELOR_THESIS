/*
---------------------------------------------------------------------------------------------------------------
 Filename: test06.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 05.06.2022
 Version: 1.1
 Description: Test write message to file and following read the same file and check if message was written succesfully.

 ---------------------------------------------------------------------------------------------------------------
*/

#include <stdio.h>
#include "../include/ext_rsa.h"
#include "../include/ext_file.h"

#define GAP 4    /* Size of gap, when writing into file, meaning number of elements per line in file */    

#ifdef BIT32
    #define MLEN 4   /* Length of message which is stored im message field */   
#elif defined BIT8
    #define MLEN 16   
#endif

int main(int argc, char** argv){

#ifdef BIT32
  uint32_t message[MLEN] = {0xd436e995,0x69fd32a7,0xc8a05bbc,0x90d32c49}; /* Message in HEX format with length of MLEN*/
#elif defined BIT8
  uint8_t message[MLEN] = {0xd4,0x36,0xe9,0x95,0x69,0xfd,0x32,0xa7,0xc8,0xa0,0x5b,0xbc,0x90,0xd3,0x2c,0x49};
#endif

    if(argc != 2) printf("Add filename for testing !!!  Using: test03 message\n");

    /* Writing message with MLEN length to file with GAP elements per line in file */
    int x = Write_MSG_FILE(argv[1],message,MLEN,GAP); 
    if(x){ /* Check for errors */
       printf("Error occurs: File opening problem !!!\n");
       return 1;
    }

   var* read_data = NULL;

   /* Reading message from file and store to address of pointer read_data, 
    read_data pointer will contain message of x length, function return length of message */
   x = Read_MSG_FILE(argv[1],&read_data); 

   if(x<0) {
       printf("Error occurs: Reading message from file !!!\n");
       return 1;
   } 

   for(int i=0;i<x;i++) /* Check if message was succesfull writen and read, x-> length of message */
   {
       if(read_data[i]!=message[i]){
           printf("Not success\n");
           free(read_data);
           return 1;
       }
   }

   free(read_data);
   printf("SUCCESS !!!\n");

    return 0;
}