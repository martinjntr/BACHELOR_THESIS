/*
---------------------------------------------------------------------------
 Filename: oaep.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 20.05.2022
 Version: 1.0

 Changes [MJ tag]: -Adding MACRO for windows secure random number genrator
                   -In MGF-1 adding support for SHA hash extensions
                   -In MGF1 replacing htonl() function
                   -Adding support for windows RNG
                   -Label method choosing
                   -Adding variable for storing result in oaep_decode()

---------------------------------------------------------------------------
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>


// MJ adding MACRO for rand()_s function
#define _CRT_RAND_S
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "oaep.h"
//#include "tiger.h"   //MJ Unusable

/* tiger hash of "CLNT" */
static const uint8_t hash_client[24] = {
  0x05, 0xAE, 0x52, 0x8F, 0x60, 0x10, 0x14, 0xCB,
  0x61, 0xE0, 0x91, 0x3D, 0x66, 0x28, 0xB4, 0x3E,
  0x33, 0x62, 0xB3, 0x70, 0xE4, 0xD6, 0x9E, 0xB6
};

/* tiger hash of "SRVR" */
static const uint8_t hash_server[24] = {
  0x72, 0xF5, 0x3D, 0x22, 0x3D, 0x8B, 0xB2, 0x26,
  0x37, 0x4C, 0xE1, 0x90, 0xB6, 0xEA, 0x05, 0xE6,
  0x5B, 0xF4, 0x71, 0x48, 0xDE, 0xAF, 0x4D, 0x4F
};


static inline  uint8_t *MGF1(uint8_t *seed, uint32_t seedLen, uint32_t maskLen, HASH_FUNCTION hash) {
  uint32_t max, mod, i, dataLen, hLen;
  uint8_t *data, *output, *tmp;


  // MJ adding hash function extensions
  if(hash == SHA1_FUNC)
      hLen = SHA1_BLOCK_SIZE;
  else if(hash == SHA256_FUNC)
      hLen = SHA256_BLOCK_SIZE;
  else if (hash == SHA512_FUNC)
      hLen = SHA512_BLOCK_SIZE; 
  else
     return NULL;

  dataLen = seedLen+4;
  data = malloc(dataLen);
  if(!data) return NULL;
  memcpy(data, seed, seedLen);

  mod = maskLen % hLen;
  max = mod ? ((maskLen-mod)/hLen)+1 : (maskLen/hLen);
  output = malloc(max*hLen);
  if(!output) {
    free(data);
    return NULL;
  }
  tmp = output;

  for(i=0; i<max; i++) {

    /*
    MJ removing htonl() and replacing 
    with algorithm on Little Endian conversion
    */

    uint8_t* s = (uint8_t*)&i; 
   *(uint32_t *)(data+seedLen) = (uint32_t)(s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3]);
    // MJ *(uint32_t *)(data+seedLen) = htonl(i);
    // MJ tiger(data, dataLen, tmp);
    
    // MJ Choosing right hash function
    if(hash == SHA1_FUNC)
      SHA1(data, dataLen, tmp);
    else if(hash == SHA256_FUNC)
      SHA256(data,dataLen,tmp);
    else if(hash == SHA512_FUNC)
      SHA512(data,dataLen,tmp);
    else{
      free(data);
      free(output);
      return NULL;
    }

    tmp += hLen;
  }
  free(data);
  return output;
}

static inline  int32_t fill_random(uint8_t *dest, uint32_t len) {

// MJ adding support for Windows RNG
#ifdef __linux__

  int32_t fd, bytes;
  
  fd = open("/dev/urandom", O_RDONLY);
  if(fd == -1) return -1;
  bytes = read(fd, dest, len);
  close(fd);
 
  if(bytes != (ssize_t)len) return -1;
 
#elif defined _WIN32
  unsigned int num;

  for (int i = 0; i < len; i++) {
      errno_t err = rand_s(&num);
      if(err != 0) return -1;
      dest[i] = (uint8_t)num;
  } 

#endif
 
 return 0;
}

/* possibly? resist linearization */
static inline uint32_t is_same(const uint8_t *a, const uint8_t *b, const uint32_t len) {
  uint32_t i;
  uint64_t acc;

  acc = 0;
  for(i=0; i<len; i++)
    acc += a[i] ^ b[i];
  if(acc > 0)
    return 0;
  else
    return 1;
}

int32_t oaep_encode(uint8_t *M, uint32_t mLen, uint32_t k, lbl_t label, uint8_t *EM, HASH_FUNCTION hash) {
  uint8_t *DB, *seed, *mask;
  uint32_t dbLen, i, hLen;
  uint8_t* pHash = NULL;


  // MJ Choosing right hash functions
  if(hash == SHA1_FUNC){
     hLen = SHA1_BLOCK_SIZE;
     pHash = malloc(hLen *sizeof(unsigned char));
     if(pHash == NULL ) return -2;
     SHA1((unsigned char*)"",0,pHash); 
  }
  else if(hash == SHA256_FUNC){
     hLen = SHA256_BLOCK_SIZE;
     pHash = malloc(hLen *sizeof(unsigned char));
     if(pHash == NULL) return -2;
     SHA256((unsigned char*)"",0,pHash);
  }

  else if(hash == SHA512_FUNC){
     hLen = SHA512_BLOCK_SIZE;
     pHash = malloc(hLen *sizeof(unsigned char));
     if(pHash == NULL) return -2;
     SHA512((unsigned char*)"",0,pHash);
  }
  else
    return -2;

  if((int32_t)mLen > (int32_t)(k-2*hLen-2)) {
    free(pHash);
    return -1;
  }

  dbLen = (k-hLen-1);
  memset(EM, 0, k);
  seed = EM+1;
  DB = EM+1+hLen;
  

  /* 
    MJ MACRO print result, used for
    checking TEST VECTORS
  */

  #if defined PRINT
    printf("M: ");
    for(int i=0; i<mLen; i++){
      printf("%02X ",M[i]);
    }
    printf("\n\n");

    printf("pHash: ");
    for(int i=0; i<hLen; i++){
      printf("%02X ",pHash[i]);
    }
    printf("\n\n");

  #endif


  // MJ label choosing
  if(label == LABEL_CLIENT)
    memcpy(DB, hash_client, hLen);
  else if (label == LABEL_SERVER)
    memcpy(DB, hash_server, hLen);
  else if (label == NONE)
    memcpy(DB, pHash, hLen);

  free(pHash);
  
  DB[dbLen-mLen-1] = 0x01;
  memcpy(DB+(dbLen-mLen), M, mLen);


  // MJ for testing with TEST VECTORS
  #if defined TEST_VECT 
    uint8_t TEST_SEED[]= {
      0xaa, 0xfd, 0x12, 0xf6, 0x59, 0xca, 0xe6, 0x34, 0x89, 0xb4,
      0x79, 0xe5, 0x07, 0x6d, 0xde, 0xc2, 0xf0, 0x6c, 0xb5, 0x8f
    };

    memcpy(seed,TEST_SEED,hLen);
    
  #else
    if( fill_random(seed, hLen) == -1 ) 
      return -3;
  #endif

  mask = MGF1(seed, hLen, dbLen,hash);

  /* 
    MJ MACRO print result, used for
    checking TEST VECTORS
  */
  #if defined PRINT
    printf("DB: ");
    for(int i=0; i<dbLen; i++){
      printf("%02X ",DB[i]);
    }
    printf("\n\n");

    printf("SEED: ");
    for(int i=0; i<hLen; i++){
      printf("%02X ",seed[i]);
    }
    printf("\n\n");

    printf("dbMask: ");
    for(int i=0; i<dbLen; i++){
      printf("%02X ",mask[i]);
    }
    printf("\n\n");

  #endif

  if(!mask) return -2;
  for(i=0; i<dbLen; i++)
    DB[i] ^= mask[i];
  free(mask);


  mask = MGF1(DB, dbLen, hLen,hash);

  /* 
    MJ MACRO print result, used for
    checking TEST VECTORS
  */
  #if defined PRINT
    printf("maskedDB: ");
    for(int i=0; i<dbLen; i++){
      printf("%02X ",mask[i]);
    }
    printf("\n\n");

    printf("seedMask: ");
    for(int i=0; i<hLen; i++){
      printf("%02X ",mask[i]);
    }
    printf("\n\n");

  #endif

  if(!mask) return -2;
  for(i=0; i<hLen; i++)
    seed[i] ^= mask[i];
  free(mask);

  /* 
    MJ MACRO print result, used for
    checking TEST VECTORS
  */
  #if defined PRINT
    printf("maskedSeed: ");
    for(int i=0; i<hLen; i++){
      printf("%02X ",seed[i]);
    }
    printf("\n\n");

    printf("EM: ");
    for(int i=0; i<k; i++){
      printf("%02X ",EM[i]);
    }
    printf("\n\n");
  #endif

  return 0;
}

int32_t oaep_decode(uint8_t *EM, uint32_t k, lbl_t label, HASH_FUNCTION hash, uint8_t* decoded) {
  int32_t i, dbLen, fail, pass, hLen;
  uint8_t *mask, *DB, *seed;
  uint8_t *lHash;


  // MJ choosing right hash functions
  if(hash == SHA1_FUNC){
     hLen = SHA1_BLOCK_SIZE;
     lHash = malloc(hLen *sizeof(unsigned char));
     if(lHash == NULL ) return -2;
     SHA1((unsigned char*)"",0,lHash); 
  }
  else if(hash == SHA256_FUNC){
     hLen = SHA256_BLOCK_SIZE;
     lHash = malloc(hLen *sizeof(unsigned char));
     if(lHash == NULL) return -2;
     SHA256((unsigned char*)"",0,lHash);
  }

  else if(hash == SHA512_FUNC){
     hLen = SHA512_BLOCK_SIZE;
     lHash = malloc(hLen *sizeof(unsigned char));
     if(lHash == NULL) return -2;
     SHA512((unsigned char*)"",0,lHash);
  }
  else
    return -2;

  if((int32_t)k < (int32_t)(2*hLen+2))
    return -5;

  dbLen = k - hLen - 1;
  seed = EM+1;
  DB = EM+1+hLen;

  mask = MGF1(DB, dbLen, hLen,hash);
  if(!mask) return -2;
  for(i=0; i<(int32_t)hLen; i++)
    seed[i] ^= mask[i];
  free(mask);
  mask = MGF1(seed, hLen, dbLen,hash);
  if(!mask) return -2;
  for(i=0; i<dbLen; i++)
    DB[i] ^= mask[i];
  free(mask);

  /* TODO: is this still vulnerable to linearization? */
  fail = pass = 0;
  if(EM[0])
      fail++;
  

  else
    pass++;



  // MJ Unusable for this project
  /*
  if(label == LABEL_CLIENT){
    free(lHash);
    lHash = hash_client;
  }
  else if(label == LABEL_SERVER){
    free(lHash);
    lHash = hash_server;
  }
  */

  if(!is_same(lHash, DB, hLen))
        fail++;

  else
    pass++;
 
  free(lHash);
  for(i=hLen; i<dbLen; i++) {
    if(DB[i] != 0x00)
      break;
  }

  if(i == dbLen || DB[i] != 0x01)
      fail++;
  
  
  else
    pass++;
  pass = dbLen - i - 1;
  while(i++ < dbLen);


// MJ for storing result to output
 for(int x=0;x<pass;x++){
  decoded[x] = EM[k-pass+x];
 }
 
  if(fail)
    return -5;

  else
    return pass;
}

#if defined(TEST)
int main(int argc, char **argv) {
  int32_t i, padRet;
  uint8_t *EM, *tmp;
  uint8_t hash[3*hLen];

  if(argc != 2) {
    printf("Usage\n");
    return -1;
  }
  memset(hash, 0xCD, sizeof(hash));
  tiger((uint8_t *)argv[1], strlen(argv[1]), hash+hLen);
  i = 1024; /* minimum 592 */
  EM = malloc(1024/8);
  if(!EM) {
    printf("Unable to allocate memory for encoded message.\n");
    return -1;
  }

  padRet = oaep_encode(hash, sizeof(hash), (1024/8), LABEL_CLIENT, EM);
  if(padRet < 0) {
    printf("Failed to encode message, got %d\n", padRet);
    return -1;
  }

  printf("Encoded message:\n");
  for(i=0; i<(1024/8); i++)
    printf("%02X ", EM[i]);
  printf("\n");

  padRet = oaep_decode(EM, (1024/8), LABEL_CLIENT);
  if(padRet < 0) {
    printf("Failed to decode message, got %d\n", padRet);
    return -1;
  }
  printf("padRet is %d, hash is %d bytes\n", padRet, sizeof(hash));

  printf("Decoded message:\n");
  tmp = EM;
  printf("Y:\t\t%02X\n", *tmp);
  tmp++;
  printf("Seed:\t\t");
  for(i=0; i<(int32_t)hLen; i++, tmp++)
    printf("%02X", *tmp);
  printf("\nDB/lHash':\t");
  for(i=0; i<(int32_t)hLen; i++, tmp++)
    printf("%02X", *tmp);
  printf("\nDB/PS+0x01:\t");
  for(i=0; !tmp[i]; i++)
    printf("%02X", tmp[i]);
  printf("%02X\n", tmp[i]);
  tmp += i + 1;
  printf("M:\t\t");
  for(i=0; i<padRet; i++, tmp++)
    printf("%02X", *tmp);
  printf("\n");

  free(EM);
  return 0;
}
#endif
