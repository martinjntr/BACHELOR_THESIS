/*
---------------------------------------------------------------------------
 Filename: ext_bignum.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 11.05.2022
 Version: 1.1
 Description: Source code contains functions for print, convertion bignum 
              to other formats. Also contains function for
              generate cryptographical secure random number.
            
---------------------------------------------------------------------------
*/

#define _CRT_RAND_S
#include <stdlib.h>

#include "../include/ext_bignum.h"

void print_bignum(bignum a)
{
  int i;   
  if (a.sign == -1)  printf("-");
    
  /* print bignum in format (reordered) in specific format */
  for (i = a.size-1; i >= 0; i--) 
  {
    #ifdef BIT8
     printf("%02hhX ",(uint8_t)a.tab[i]); 
    #elif defined BIT32
     printf("%08lX ",(unsigned long)a.tab[i]);
    #endif
  }
  printf("\n");
}

bignum msg2bignum(var* msg, int length){
  
  bignum ret;
  ret.sign = 1;

  int i=0;

  /* 
    first zeroes in message we cannot assign to bignum, 
    it wull we useless 
  */ 
  

  while(msg[i] == 0)  
    i++;
  
  ret.size = length - i; /* length message without zeroes */

  ret.tab = (block*) malloc(sizeof(block) * ret.size);
  memset(ret.tab,0x00, sizeof(block)*ret.size);


  /* passing message to bignum in reverse order */
  for(int c=0 ;i<length; i++, c++) 
    ret.tab[ret.size -1 -c] = msg[i];

  return ret;
}

int bignum2msg(bignum a,var* data, int len)
{
  if(data == NULL) return -1;

  /*check if data alocation space is higher than bignum size */
  if(a.size > len) return -2; 
 
  /* 
    count starting position for storing data before data will be 
    space padded with zeroes
  */
  int length = len - a.size;  

  for(int i=a.size-1; i>=0; i--) /*assign bignum to data*/
    data[length++] = a.tab[i];
  
   return a.size;
}


bignum generate_secure_random(int length)
{
    bignum ret;

    if (length == 0) { /* result will be 1 random number [0]*/ 
        ret.sign = 1;
        ret.size = 1;
        ret.tab = (block *)malloc(sizeof(block));
        ret.tab[0] = 0;
        return ret;
    }

    ret.sign = 1;
    /* 
      count bignum size, E can be 8 [8-bit compiling process] and 
      32 [32-bit compiling process]
    */
    ret.size = length / E;

    /* if rest after modulo division occurs, increase bignum size*/ 
    if (length % E != 0) 
        ret.size++;
    ret.tab = (block *)malloc(sizeof(block)*ret.size);
  
#if defined (__linux__)
    #include <fcntl.h>
    #include <unistd.h>
   int fd = open("/dev/urandom", O_RDONLY);
   if(fd == -1) exit(1);
   /* Write secure random numbers on Linux plafform */
   int bytes = read(fd, ret.tab, sizeof(block)*ret.size); 

   if(bytes != sizeof(block)*ret.size) exit(1);

   while((ret.tab[0] & MASK || ret.tab[0] < HITMASK) == 0){
     bytes = read(fd, ret.tab, sizeof(block));
     if(bytes != sizeof(block)) exit(1);
   }

   close(fd);

#elif defined (_WIN32)
   uint32_t num;
   /* Write secure random numbers on Windows platform */
   for (int i = 0; i < ret.size; i++) {  
      errno_t err = rand_s(&num);
      ret.tab[i] = (var)num;
      if(err != 0) exit(1);
    }
    
    while((ret.tab[0] & MASK) == 0 || ret.tab[0] < HITMASK){
      errno_t err = rand_s(&num);
      ret.tab[0] = (var)num;
      if(err != 0) exit(1);
    }

#endif 

  for(int x=0;x<ret.size;x++)   /* Apply MASK restriction variable */
    ret.tab[x] &= MASK;

  ret.tab[0]|= (block)0x1;   /* First number cannot be 0 */
  ret.tab[ret.size-1]|= (block)0x1;   /* First number cannot be 0 */
  return ret;
}

bignum generate_secure_randomprime(int length)
{
    bignum p = generate_secure_random(length);
    /* Testing if number is prime number using miller-rabin test */
    while (!millerrabin(p, TEST_CNT)) { 
        free(p.tab);
        p.tab = NULL;
        p = generate_secure_random(length);
    }

    return p;
}

void reverse_4bytes(uint8_t* message, int len)
{
  uint8_t swap;

  for(int i=0;i<len;i+=4)
   {
    swap = message[i];
    message[i] = message[i+3]; /* exchange 1 with 4 byte */
    message[i+3] = swap;
 
    swap =message[i+1];   /* exchange 2 with 3 byte */
    message[i+1] = message[i+2];
    message[i+2] = swap;
   }
}
