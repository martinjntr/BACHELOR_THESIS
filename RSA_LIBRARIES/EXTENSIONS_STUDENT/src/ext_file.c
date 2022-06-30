/*
---------------------------------------------------------------------------
 Filename: ext_file.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 11.05.2022
 Version: 1.3
 Description: Source code contains declaration functions for reading and 
              writing message, public and private keys to file format.
---------------------------------------------------------------------------
*/

#include <stdio.h>

#include "../include/ext_file.h"

void WR_FILE(FILE* fp, bignum* data, int len, int width)
{
  /* Length of bignumber in bytes */
  uint32_t size = data->size * sizeof(var);

#ifdef BIT8
  uint32_t i=0;
  while (size--) {
		if ((i % width) == 0 && i)   /* Testing for width */
			fprintf(fp,"\n");

    /* Write to file with specific format */
		fprintf(fp, "%02hhX ",(uint8_t)data->tab[size]); 
		i++;
	}
#elif defined BIT32
  var result;
  uint8_t* ptr; /* Pointer for converting uint32_t to uint8_t */
 
  /* First number in bignumber format */
  result = data->tab[data->size -1];
  ptr = (uint8_t*)&result; /* Assign pointer to first number */
  
  int count=sizeof(var);

  /* 
    If first number in bignum format contains zeroes at beginning, 
    zeroes will be deleted 
  */
  while(ptr[--count] == 0); 

  /* Write fisrt number to file without zeroes */
  for(int i=count; i>=0; i--, size--){
    /* Testing for width */
    if ((size % width) == 0 && size != (data->size*sizeof(var)))
			    fprintf(fp,"\n");
    fprintf(fp, "%02hhX ",ptr[i]);
  }

  for(int i=data->size-2; i>=0; i--){ /* Write bignumber fo file */
    result = data->tab[i]; /* Assign number to temporary variable */
    
    /* Add 32-bit number to uint8_t pointer array */
    ptr = (uint8_t*)&result;

    /* Cycle for crossing 4bytes from one uint32_t number */
    for(int x=sizeof(var)-1; x>=0; x--, size--){ 

      /* Testing for width */
      if ((size % width)==0 && (i != data->size -2)) 
			    fprintf(fp,"\n");

      /* Write to file one uint8_t number */
      fprintf(fp, "%02hhX ",ptr[x]); 
    }
  }
#endif
    fprintf(fp,"\n");

}

int Write_MSG_FILE(const char* filename, var* data, int len, int width)
{
  FILE* fp;

  if((fp = fopen(filename,"w")) == NULL) return -1;

  /* Write beginning MSG format[HEX] message to file */
  fprintf(fp,"%s\n",bmsg); 

  #ifdef BIT8

  for(int i=0;i<len;i++){  
        if((i % width) == 0 && i) /* Testing for width */
             fprintf(fp,"\n");
        fprintf(fp,"%02hhX ",data[i]);
    }

  #elif BIT32

  /* Convert to uint8_t, it is usable if number is uint32_t */
  uint8_t* result = (uint8_t*) data; 
  len = len * sizeof(var); /* Length of data field in bytes */

  reverse_4bytes(result,len);

  for(int i=0;i<len;i++){  
        if((i % width) == 0 && i)
             fprintf(fp,"\n");
        fprintf(fp,"%02hhX ",result[i]);
    }

  #endif

  fprintf(fp,"\n");

  /* Write ending MSG format message to file */
  fprintf(fp,"%s\n",emsg); 
  fclose(fp);
  return 0;
}


int Read_MSG_FILE(const char* filename,var** msg){
    
  FILE* fp = fopen(filename,"r");
  if(fp == NULL) return -1;

  /* Field fro storing FILE lines as string */
  uint8_t s[FILE_LEN][FILE_LINE_LEN]; 

  /* Field for storing FILE beginning or ending format message */
  uint8_t data[FILE_LINE_LEN]; 

  /* Initialization, set all fileds memebers to 0 */
  memset(data,0x00,FILE_LINE_LEN);
  memset(s, 0x00, FILE_LEN * FILE_LINE_LEN);	

  /* Check if correct type of FILE is reading */
  if(fgets((char*) data,FILE_LINE_LEN,fp) != NULL){ 
      if(memcmp(data,bmsg,strlen((const char*)bmsg)-1)){
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
  
  int counter = count;
  /* Lenght of message in specific format */
  count = count/sizeof(var) + (count%sizeof(var) ? 1:0);
  uint8_t* read_data = (uint8_t*)malloc(counter);

  uint8_t *end;
  long number;
 
  counter = 0;
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
      read_data[counter++] = (uint8_t)number;
      res = end;
    }
  }

  *msg = (var*)malloc(count * sizeof(var));
  if(*msg == NULL) return -3;

  /* Copy numbers from read_data to *msg of counter length */
  memcpy(*msg,read_data,counter);
  free(read_data);

  fclose(fp);
  return count; /* Length of message */
}

int WriteRSA_Key(const char* filename,rsa_key* key, int width, 
FILE_KEY type)
{

  FILE* fp;
  if((fp = fopen(filename,"w")) == NULL)return -1;

  int err;
   /* 
    Write specific beginning format message into file based on 
    FILE_KEY type
  */
  err = (type == PUBLIC_KEY) ? fprintf(fp,"%s\n[e] \n",bpubk) :
  ( (type == PRIVATE_KEY) ? fprintf(fp,"%s\n[d] \n",bpk) : -1); 
  if(err <=0) return -2;
      
  bignum* result;

  /* 
    Store into result variable correct type of exponent[e,d] based 
    on FILE_KEY type 
  */
  result = (type == PUBLIC_KEY) ? &key->pub.e : 
  ((type == PRIVATE_KEY) ? &key->priv.d : NULL);

  /* Write exponet to file in specific format */
  WR_FILE(fp,result,result->size,width); 

  fprintf(fp,"[n]\n");

  /* Write RSA modulus into file */
  WR_FILE(fp,&key->pub.n,key->pub.n.size,width);
   
  /* 
    Write specific ending format message into file based on 
    FILE_KEY type
  */
  err = (type == PUBLIC_KEY) ? fprintf(fp,"%s\n",epubk) :
  ((type == PRIVATE_KEY) ? fprintf(fp,"%s\n",epk) : -1);

  fclose(fp);
  return 0;
}

int ReadRSA_Key(const char* filename, rsa_key* key, FILE_KEY type)
{
  FILE* fp = fopen(filename, "r");
  if(fp == NULL) return -1;

  /* Field for storing FILE beginning or ending format message */
  uint8_t data[FILE_LINE_LEN]; 
  memset(data,0x00,FILE_LINE_LEN);

  /* Read first line in FILE and check if correct file is reading */
  if(fgets((char*) data,FILE_LINE_LEN,fp) != NULL){ 
    if(type == PUBLIC_KEY){

      /* Compare reading data and format */
      if(memcmp(data,bpubk,strlen((const char*)bpubk)-1)){ 
        fclose(fp);
        return -2;        
      }

    }

    else if(type == PRIVATE_KEY){

      /* Compare reading data and format */
      if(memcmp(data,bpk,strlen((const char*)bpk)-1)){ 
        fclose(fp);
        return -2;        
      }
    }
    else return -3;
  }

  fgets((char*) data,FILE_LINE_LEN,fp); /* Read exponent [e] or [d] */
 
  /* Assign to temporary variable correct RSA exponent */
  bignum* res  = (type == PUBLIC_KEY) ? &key->pub.e : &key->priv.d;

  /* 
    Read exponent number from FILE, reading will be stopped when [n] 
    line will be loading 
  */
  int err = READ_BLOCK(fp,"[n]",res);
  if(err < 0) return err;


  /* Assign to temporary variable modulus and ending message from FILE */
  res  = (type == PUBLIC_KEY) ? &key->pub.n : &key->priv.n;
  const char* msg_type = (type == PUBLIC_KEY) ? (const char*)epubk : 
  (const char*)epk;
  
  /* 
    Read modulus number from FILE, reading will be stopped when ending 
    FILE line will be loading
  */
  err = READ_BLOCK(fp,msg_type,res);
  if(err < 0){
    fclose(fp);
    return err;
  }

  fclose(fp);         
  return 0;
}

int READ_BLOCK(FILE* fp,const char* target, bignum* a){
 
  /* Field fro storing FILE lines as string */
  uint8_t s[FILE_LEN][FILE_LINE_LEN]; 
  memset(s, 0x00, FILE_LEN * FILE_LINE_LEN);

  int i=0, count=0, len=0;

  while(!feof(fp)){
    /* Read one string from FILE and store to field */
    fgets((char*)s[i], FILE_LINE_LEN, fp); 

    /* Stop reading after target is matched  */
    if(memcmp(s[i],target,strlen(target))==0) break; 

    /* Len of string without newline separator */
    len = strlen((char*)s[i])-1;
    s[i][len] = '\0';
    count += len / 3; /* Count of numbers in string */
    i++; /* Increment count of strings */
  }

  int counter = count;

  /* Length of storage for result */
  count = count/sizeof(var) + (count%sizeof(var) ? 1:0); 

  a->sign = 1;
  a->size= count;
  a->tab = (block*)malloc(count * sizeof(block));
  if(a->tab == NULL) return -4;
  
  memset(a->tab,0x00,count * sizeof(block));

  uint8_t *end;
  long number;

  uint8_t* temporary = (uint8_t*)malloc(counter);
  if(temporary == NULL){
    free(a->tab);
    return -4;
  }
  
  uint8_t* res = NULL;

  int tmp_len = counter;

  /* From every string from s field read numbers */
  for(int x =0;x<i;x++){ 
    
    res = (uint8_t*)s[x];
    for(;;){
      /* Read one number from string and move pointer */
      number = strtol((const char*)res, (char**)&end, HEX_FORMAT);
      if (res == end)
        break;

      /* Store number in reverse order */
      temporary[--tmp_len] = (uint8_t)number; 
      res = end;
    }
  }
  

  #ifdef BIT8
    for(int p=0;p<count;p++) /* Assign data to result variable */
      a->tab[p] = temporary[p];

  #elif defined BIT32
  /* Check if number of bytes is higher than 4bytes */
  if(counter > (sizeof(var) -1)){
    int c=0;

    /* 
      Copy 4bytes to one block [size of one variable, for 32-bit number 
      is it int128_t which store 32 bit number] variable, 
      we work with 32-bit number 
    */
    for(int p=0; p<counter ;p+=sizeof(var),c++)
      memcpy(a->tab+c,temporary+p,sizeof(var));
  
    /* If number of bytes in smaller than 4 assign to last byte 0 */
    if(counter % sizeof(var))
      a->tab[c-1]&= 0x00FFFFFF;
  }
  else
    /* Copy bytes of size [counter] to one block number */
    memcpy(a->tab,temporary,counter); 

  #endif

  free(temporary);
  return 0;
}