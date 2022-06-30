/*
---------------------------------------------------------------------------------------------------------------
 Filename: ext_file.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 06.03.2022
 Version: 1.1
 Description: Source code contains declaration functions for reading and writing message, public and private keys
              to file format.
 ---------------------------------------------------------------------------------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ext_file.h"
#include "ext_rsa.h"


void WR_FILE(FILE* fp, uint8_t* data, int len, int width)
{
  uint32_t i =0;
  while (len--) {
		if ((i % width) == 0 && i) /* Testing for width */
			fprintf(fp,"\n");
		fprintf(fp, "%02hhx ", data[len]); /* Write to file one byte */
		i++;
	}
  
  fprintf(fp,"\n");
}


int Write_MSG_FILE(const char* filename, uint8_t* data, int len, int width)
{
  FILE* fp;
  if((fp = fopen(filename,"w+")) == NULL) return -1;

  fprintf(fp,"%s",bmsg); /* Write beginning MSG format message to file */

  for(int i=0;i<len;i++){   /* Writing data to file */
    if((i % width) == 0)
          fprintf(fp,"\n");
    fprintf(fp,"%02hhX ",data[i]);
  }

  fprintf(fp,"\n");
 
  fprintf(fp,"%s\n",emsg); /* Write ending MSG format message to file */
  fclose(fp);
  return 0;
}


int Read_MSG_FILE(const char* filename,uint8_t** data){
  
  FILE* fp = fopen(filename,"r");
  if(fp == NULL) return -1;

  uint8_t s[FILE_LEN][FILE_LINE_LEN]; /* Field fro storing FILE lines as string */
  uint8_t frmt_msg[FILE_LINE_LEN]; /* Field for storing FILE beginning or ending format message */

  /* Initialization, set all fileds memebers to 0 */
  memset(frmt_msg,0x00,FILE_LINE_LEN);
  memset(s, 0x00, FILE_LEN * FILE_LINE_LEN);	

  /* Check if correct type of FILE is reading */
  if(fgets((char*) frmt_msg,FILE_LINE_LEN,fp) != NULL){ 
      if(memcmp(frmt_msg,bmsg,strlen((const char*)bmsg)-1)){
        fclose(fp);
        return -2;        
      }
  }

  int i=0, count=0, len=0;

  while(!feof(fp)){
    fgets((char*)s[i], FILE_LINE_LEN, fp); /* Gets one line from FILE */

    /* If target line is reading, reading will be stopped */
    if(memcmp(s[i],emsg,strlen((const char*)emsg)-1) == 0) break;
    len = strlen((char*)s[i])-1;
    s[i][len] = '\0';
    count += len / 3; /* Count of numbers in string */
    i++; /* Increment number of strings */
  }
  

  *data = (uint8_t*)malloc(count);
  if(*data == NULL) return -3;

  uint8_t *end;
  long number;
 
  count = 0;
  uint8_t* res = NULL;

  /* Read every string and convert every string to set of numbers */
  for(int x =0;x<i;x++){
    res = (uint8_t*)s[x];
    
    for(;;){
      /* Read one number from string and move pointer */
      number = strtol((const char*)res, (char**)&end, 16);
      if (res == end)
        break;
      /*  Assign number to temporary variable */
      *(*(data) + count++) = (uint8_t)number;
      res = end;
    }
  }

  fclose(fp);
  return count; /* Length of message */
}


int ReadRSA_KEY(const char* filename,RSA_KEY* key,TYPE_KEY type)
{
  FILE* fp = fopen(filename, "r");
  if(fp == NULL) return -1;

  /* Field for storing FILE beginning or ending format message */
  uint8_t data[FILE_LINE_LEN]; 
  memset(data,0x00,FILE_LINE_LEN);

  /* Read first line in FILE and check if correct file is reading */
  if(fgets((char*) data,FILE_LINE_LEN,fp) != NULL){ 
    if(type == PUBLIC){
      if(memcmp(data,bpubk,strlen((const char*)bpubk)-1)){ /* Compare reading data and format */
        fclose(fp);
        return -2;        
      }

    }

    else if(type == PRIVATE){
      if(memcmp(data,bpk,strlen((const char*)bpk)-1)){ /* Compare reading data and format */
        fclose(fp);
        return -2;        
      }
    }
    else return -3;
  }

  fgets((char*) data,FILE_LINE_LEN,fp); /* Read exponent [e] or [d] */
 
  struct bn res;
  bignum_init(&res);

  /* Read exponent number from FILE, reading will be stopped when when [n] line will be loading */
  int err = READ_BLOCK(fp,"[n]",&res);
  if(err < 0) {
    fclose(fp);
    return err;
  }
  /* Assign to temporary variable correct RSA exponent */
  if(type == PUBLIC) bignum_assign(&key->pub.e,&res);
  else bignum_assign(&key->priv.d,&res); /* Type PRIVATE */
  
  bignum_init(&res);

  /* Assign to temporary variable ending message from FILE */
  const char* msg_type = (type == PUBLIC) ? (const char*)epubk : (const char*)epk;
  
  /* Read modulus number from FILE, reading will be stopped when when ending FILE line will be loading */
  err = READ_BLOCK(fp,msg_type,&res);
  if(err < 0) {
    fclose(fp);
    return err;
  }

  /* Assign to temporary variable modulus */
  if(type == PUBLIC) bignum_assign(&key->pub.n,&res);
  else bignum_assign(&key->priv.n,&res); /* Type PRIVATE */

  fclose(fp);         
  return 0;
}

int READ_BLOCK(FILE* fp,const char* target, struct bn* a){

  uint8_t s[FILE_LEN][FILE_LINE_LEN]; /* Field fro storing FILE lines as string */
  memset(s, 0x00, FILE_LEN * FILE_LINE_LEN);

  int i=0, count=0, len=0;

  while(!feof(fp)){
    fgets((char*)s[i], FILE_LINE_LEN, fp); /* Read one string from FILE and store to field */

    if(memcmp(s[i],target,strlen(target))==0) break; /* Stop reading after target is matched  */

    len = strlen((char*)s[i])-1; /* Len of string without newline separator */
    s[i][len] = '\0';
    count += len / 3; /* Count of numbers in string */
    i++; /* Increment count of strings */
  }

  int counter = count;
 
  bignum_init(a);

  uint8_t *end;
  long number;

  uint8_t* temporary = (uint8_t*)malloc(counter);
  if(temporary == NULL)
    return -4;

  uint8_t* res = NULL;

  count =0;

  for(int x =0;x<i;x++){ /* From every string from s field read numbers */
    
    res = (uint8_t*)s[x];
    for(;;){
      /* Read one number from string and move pointer */
      number = strtol((const char*)res, (char**)&end, HEX_FORMAT);
      if (res == end)
        break;

      /* Store number in reverse order */
      temporary[count++] = (uint8_t)number; 
      res = end;
    }
  }
  
  /* Convert uint8_t array to BN */
  int err= MSG2_BN(temporary,count,a);
  if(err < 0){
    free(temporary);
    return -5;
  }

  free(temporary);
  return 0;
}