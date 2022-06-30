/*
---------------------------------------------------------------------------------------------------------------
 Filename: ext_rsa.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 18.02.2022
 Version: 1.0
 Description: Source code contains function for RSA key genrate, encrypt and decrypt with OAEP padding or NON padding.
              Also contains function for destory allocation memory for RSA key pair.
 ---------------------------------------------------------------------------------------------------------------
*/

#include <stdlib.h>

#include "../include/ext_rsa.h"


int key_gen(rsa_key* new_key, int len)
{
    bignum p, q, phi_n;
    bignum t0, t1, bgcd;
    bignum ONE = digit2bignum(1);
#if defined TEST_VECT && defined BIT8

/* test vectors: https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf */
  unsigned char p_num[] = { 0xee,0xcf,0xae,0x81,0xb1,0xb9,0xb3,0xc9,0x08,0x81,0x0b,0x10,0xa1,0xb5,0x60,0x01,0x99,0xeb,0x9f,0x44,0xae,0xf4,0xfd,0xa4,0x93,0xb8,0x1a,0x9e,0x3d,0x84,0xf6,0x32,0x12,0x4e,0xf0,0x23,0x6e,0x5d,0x1e,0x3b,0x7e,0x28,0xfa,0xe7,0xaa,0x04,0x0a,0x2d,0x5b,0x25,0x21,0x76,0x45,0x9d,0x1f,0x39,0x75,0x41,0xba,0x2a,0x58,0xfb,0x65,0x99};

  unsigned char q_num[] = {0xc9,0x7f,0xb1,0xf0,0x27,0xf4,0x53,0xf6,0x34,0x12,0x33,0xea,0xaa,0xd1,0xd9,0x35,0x3f,0x6c,0x42,0xd0,0x88,0x66,0xb1,0xd0,0x5a,0x0f,0x20,0x35,0x02,0x8b,0x9d,0x86,0x98,0x40,0xb4,0x16,0x66,0xb4,0x2e,0x92,0xea,0x0d,0xa3,0xb4,0x32,0x04,0xb5,0xcf,0xce,0x33,0x52,0x52,0x4d,0x04,0x16,0xa5,0xa4,0x41,0xe7,0x00,0xaf,0x46,0x15,0x03};

  p.size = 64; /*size of data which are store in field */
  q.size = 64;

#elif defined TEST_VECT && defined BIT32
/* test vectors: https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf in 32-bit format*/
  unsigned int p_num[] = {0xeecfae81,0xb1b9b3c9,0x08810b10,0xa1b56001,0x99eb9f44,0xaef4fda4,0x93b81a9e,0x3d84f632,0x124ef023,0x6e5d1e3b,0x7e28fae7,0xaa040a2d,0x5b252176,0x459d1f39,0x7541ba2a,0x58fb6599};

  unsigned int q_num[] = {0xc97fb1f0,0x27f453f6,0x341233ea,0xaad1d935,0x3f6c42d0,0x8866b1d0,0x5a0f2035,0x028b9d86,0x9840b416,0x66b42e92,0xea0da3b4,0x3204b5cf,0xce335252,0x4d0416a5,0xa441e700,0xaf461503};

 p.size = 16; /*size of data which are store in field */
 q.size = 16;
#endif
 

#if defined TEST_VECT

 p.sign = 1;
 p.tab = (block*) malloc(sizeof(block)*p.size);
 if(p.tab==NULL) return -1;

 q.sign = 1;
 q.tab = (block*) malloc(sizeof(block)*p.size);
 if(p.tab==NULL){
   free(p.tab);
   return -1;
 }


 for(int i=0;i<p.size;i++){   /* Assign data to bignum p,q*/
   p.tab[i] = (block)p_num[p.size -1 -i];
   q.tab[i] = (block)q_num[q.size -1 -i];
}

 new_key->pub.e.sign = 1;
 new_key->pub.e.size = 1;
 new_key->pub.e.tab= (block*)malloc(sizeof(block));

 if(new_key->pub.e.tab == NULL){
   free(q.tab);
   free(p.tab);
   return -1;
 }
 new_key->pub.e.tab[0] =(block) 0x11;  /* Assign number to public exponent */
 new_key->pub.n = mult(p, q);  /* Compute p*q and store to n*/

  #if defined PRINT
  printf("TESTING WITH TEST VECTORS FROM:\n"
  "https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf\n"
  "--------------------------------------------------------------------------\n\n\n");


  printf("P: ");
  print_bignum(p);
  printf("\n");

  printf("Q: ");
  print_bignum(q);
  printf("\n");

  printf("E: ");
  print_bignum(new_key->pub.e);
  printf("\n");
  #endif

#else
    int size = len / 8 /sizeof(var); /* Size of modulus for specific format[8-bit, 32-bit compilation]*/

    p = generate_secure_randomprime(len/2); /* Random number which will have size of len/2 bits */
    q = generate_secure_randomprime(len/2); 

    while (compare(p, q) == 0) { /* If primenumbers are the same, generate new primenumber q */
        free(q.tab);
        q = generate_secure_randomprime(len/2);
    }

    new_key->pub.n = mult(p, q);  /* Compute p*q and store to n*/


   /* Check if modulus has right size, avoiding  m > n cause overflow in RSA */
   while(new_key->pub.n.size != size || new_key->pub.n.tab[new_key->pub.n.size-1] < HITMASK){ 
     free(p.tab);
     free(q.tab);
     free(new_key->pub.n.tab);
     p = generate_secure_randomprime(len/2);
     q = generate_secure_randomprime(len/2);

    while (compare(p, q) == 0) { /* If primenumbers are the same, generate new primenumber q */
        free(q.tab);
        q = generate_secure_randomprime(len/2);
    }

    new_key->pub.n = mult(p, q);  /* Compute p*q and store to n*/
   }

    /* Most commonly value used in cryptographic standards for public exponent */
    new_key->pub.e = str2bignum("65537");

#endif

#ifdef PRINT
    printf("N: ");
    print_bignum(new_key->pub.n);
    printf("\n");
#endif

    copy(&new_key->priv.n,new_key->pub.n); /* Assign the same RSA modulus in public key to private key*/
    t0 = sub(p, ONE);       /* to = p-1 */
    t1 = sub(q, ONE);       /* t1 = q-1 */
    phi_n = mult(t0, t1);   /* compute (p-1)*(q-1) */
    free(t0.tab);
    free(t1.tab);

    while (1) {
        bgcd = gcd(new_key->pub.e, phi_n);  /* Test for GCD(e,phi_n) == 1 */ 
        if (compare(bgcd, ONE) == 0) {
            free(bgcd.tab);
            /* Find d using extended Euclideand aldorithm d = e^-1 mod phi_n   d is multiplicative inverse */
            new_key->priv.d = inverse(new_key->pub.e, phi_n); 
            break;
        }

        free(bgcd.tab);

        /* If GCD(e,phi_n) != 1 generate new public exponent*/
        int e_len;
        do {
            e_len = rand() % (length(new_key->pub.n)); /* Choose random value from 0 - RSA modulus size[n] */
        } while (e_len <= 1);

        do {
            free(new_key->pub.e.tab);
            new_key->pub.e = genrandom(e_len);
        } while (iszero(new_key->pub.e) || isone(new_key->pub.e));
    }

    #ifdef PRINT
      printf("D: ");
      print_bignum(new_key->priv.d);
      printf("\n");
    #endif
    
    free(ONE.tab);
    free(p.tab);
    free(q.tab);
    free(phi_n.tab);
    
    return 0;
}

int RSA_encrypt(var* message,int mlen, rsa_public_key key, var* encrypted, uint32_t len, int padding)
{ 
    bignum m;
    int err;
    int size_rsa = len/8; /* Size of RSA in bytes */

    if(size_rsa/sizeof(var) < mlen) return -1; /* Check if m < modulus */

    memset((uint8_t*)encrypted,0x00,size_rsa); /* Set all items in encrypted filed to 0*/

    if(padding == OAEP_PKCS1_PADDING)
    {
        HASH_FUNCTION hash = SHA1_FUNC;    /* we can use SHA1, SHA256 and SHA512 hash function */

           #ifdef BIT32
             uint8_t* message_convert = (uint8_t*)message; /* Add 8-bit pointer to look on 32-bit variable*/
             reverse_4bytes(message_convert,mlen * sizeof(uint32_t)); /* reverse every 4 bytes in message */

             uint8_t* encrypted_convert = (uint8_t*)encrypted;  /* Add 8-bit pointer to look on 32-bit variable*/

             /* Calculate OAEP padding for RSA */
             err = oaep_encode(message_convert,mlen*sizeof(uint32_t),size_rsa,NONE,encrypted_convert,hash);
             if(err) return err;

             reverse_4bytes(encrypted_convert,size_rsa); /* reverse every 4 bytes */
             m = msg2bignum(encrypted,size_rsa/sizeof(uint32_t));  /* Assign encrypted OAEP to bignum */    

           #else
            err = oaep_encode(message,mlen,size_rsa,NONE,encrypted,hash); /* Calculate OAEP paddind for RSA */                
            if(err) return err;

            m = msg2bignum(encrypted,size_rsa); /* Assign encrypted OAEP to bignum */ 
           #endif
    }

    else if (padding == NONE_PADDING) 
      m = msg2bignum(message,mlen); /* Assign message to bignum */
    else 
      return -4;
    
    
    bignum data =  expmod(m, key.e, key.n);     /* Compute m^e mod n */
    int result;
    
    /* convert bignum to message format[uint8_t , uint32_t] */
    result = bignum2msg(data,encrypted,size_rsa/sizeof(var)); 
    
    if(result == -2){
        free(m.tab);       
        return -2;
    }

    free(data.tab);
    free(m.tab);

   return result; /* Return size of encrypted message */
}

int RSA_decrypt(var* encrypted_message, rsa_private_key key, var* decrypted,uint32_t len, int padding)
{
    int size_rsa = len/8; /* Size of RSA in bytes */

    bignum c = msg2bignum(encrypted_message,size_rsa/sizeof(var)); /* Convertion message to bignum format */

    bignum data = expmod(c, key.d, key.n);             /* Compute c^d mod n */

    free(c.tab); 
  
    int result;
    memset((uint8_t*)decrypted,0x00,size_rsa);

    if(padding == OAEP_PKCS1_PADDING){
      HASH_FUNCTION hash = SHA1_FUNC; /* we can use SHA1, SHA256 and SHA512 hash function */

      #ifdef BIT8
        result = bignum2msg(data,decrypted,size_rsa);  /* Convertion bignum to message format */
                  
       if(result < 0){ /* Check for convertion errors */
        free(data.tab);
        return result;
       }
      
       result = oaep_decode(decrypted,size_rsa,NONE,hash,decrypted);
      
       if(result <= 0){ /* Check for oaep decoding errors */
         free(data.tab);
         return result;
       } 

       #elif defined BIT32
        result = bignum2msg(data,decrypted, size_rsa/sizeof(var)); /* Convertion bignum to message format */
              
        if(result < 0){ /* Check for convertion errors */
        free(data.tab);
        return result;
       }

       uint8_t* decrypted_convert = (uint8_t*) decrypted;
       reverse_4bytes(decrypted_convert,size_rsa);
       
       result = oaep_decode(decrypted_convert,size_rsa,NONE,hash,decrypted_convert); 
       if(result < 0){   /* Check for oaep decoding errors */
         free(data.tab);
         return result;
       } 

       result = (result % sizeof(uint32_t)) ? ((result > 4) ? result+1 : 1 ) : (result/sizeof(uint32_t)); /* Compute length of decoding message */
       #endif
 
    }

    else if(padding == NONE_PADDING) 
      result = bignum2msg(data,decrypted,data.size); /* Convertion bignum to message format */
    
    else 
      return -4;

    free(data.tab);

  return result;
}

void RSA_key_free(rsa_key* key){
  if(key == NULL) return;
  
  /* Free public and  private exponent, RSA modulus which is stored public and private key*/
  free(key->priv.d.tab);
  free(key->pub.e.tab);
  free(key->priv.n.tab);
  free(key->pub.n.tab);
}

void Private_key_free(rsa_key* key){
  if(key == NULL) return;

  /* Free private RSA key */
  free(key->priv.d.tab);
  free(key->priv.n.tab);
}

void Public_key_free(rsa_key* key){
   if(key == NULL) return;

   /* Free public RSA key */
   free(key->pub.e.tab);
   free(key->pub.n.tab);
}
