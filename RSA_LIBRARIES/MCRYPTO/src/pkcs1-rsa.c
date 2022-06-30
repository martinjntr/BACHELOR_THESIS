
/*
---------------------------------------------------------------------------
 Filename: pkcs1-rsa.c
 Author: Martin Janitor
 Bachelor thesis: RSA with OAEP padding
 Date: 20.05.2022
 Version: 1.0

 Changes [MJ tag]:	- 	Adding block of code which realize conversion
						to BN format in function PKCS1_RSA_OAEP_ENCRYPT()
				    -	Adding directives for add test vectors in function
				     	PKCS1_RSA_GenKey(), PKCS1_EME_OAEP_ENC()
					-	Adding conversion to Little Endian in MGF1()

---------------------------------------------------------------------------
*/

/*--------------------------------------------------------*/
/* PKCS #1 - RSA Cryptosystem Simplified Implementation   */
/* Author : Dang Nguyen Duc, nguyenduc@icu.ac.kr          */
/* Date   : 2006/11/12                                    */
/* Note   : Bit length of modulus of ways divisible by bit*/
/*          length of a double word (i.e. 32 bits)        */
/* To do  :						  */
/*          1. Fast Decryption Using CRT                  */			  
/*--------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "mcrypto.h"
#include "pkcs1-rsa.h"
#include "hash.h"
#include "bigdigits.h"


/* Internal Functions - Forward Declaration */
static void memxor(BYTE *c, BYTE *a, BYTE *b, UINT len); 
	/* Perform c = a XOR b */

static int GenRsaPrime(DIGIT_T p[], UINT ndigits);
	/* Generate a pseudoprime of length ndigits */ /* To do: put in BigInt lib */	

static int MGF1(UINT hid, BYTE *seed, UINT seedlen, BYTE  *mask, UINT masklen);
	/* Mask Generation Function Using Hash Function */

/* Internal Functions */
static void memxor(BYTE *c, BYTE *a, BYTE *b, UINT len)
{
	while(len--)
		c[len] = a[len] ^ b[len]; 
}

static int GenRsaPrime(DIGIT_T p[], UINT ndigits)
{
	/* Generate a pseudorandom number */
	mpMakeRandom(p, ndigits);

	/*	Make sure two highest and the low bits are set.
		Having the two highest bits set means the product
		(pq) will always have its highest bit set. 
	*/
	p[ndigits - 1] |= HIBITMASK | (HIBITMASK >> 1);
	p[0] |= 0x1;

	/* Primality Testing using Miller-Rabin Method */
	while (!mpIsPrime(p, ndigits, N_TEST_PRIME)) {
		/* add 2 to p and try to test again */
		mpShortAdd(p, p, 2, ndigits);

		/* Check for overflow */
		if (!(p[ndigits - 1] & HIBITMASK))
			return -1;	/* Failed to find a prime */
	}
	
	return 0;
}

static int MGF1(UINT hid, BYTE *seed, UINT seedlen, BYTE  *mask, UINT masklen)
{
	/* Mask Generation Function Using Hash Function */
	UINT hlen;
	DWORD i;
	BYTE *hash;
	BYTE *data;
	DWORD n;
	DWORD MAX_SIZE = 0x8000;
	BYTE T[MAX_SIZE];
	int ret;
	
	/* Init Ouput */
	memset(T, 0x00, MAX_SIZE);
	
	/* masklen should be less than MAX_SIZE */
	if((hlen = HashLenQuery(hid))==0)	/* Unkown Hash Algorithm */
		return ERR_UNKNOWN_HASH;
	
	if(masklen % hlen)
		n = masklen / hlen + 1;
	else
		n = masklen / hlen;
	
	/* Preparing Hash Input/Ouput */
	data = (BYTE *)malloc(seedlen + 4);
	memcpy(data, seed, seedlen);
	
	hash = (BYTE *)malloc(hlen);
		 
	for(i=0;i<n;i++) {
		/* Constructing Hash Input */

		// MJ conversion i to Little Endian format
		BYTE* s = (BYTE*)&i; 
   		*(UINT*)(data+seedlen) = (UINT)(s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3]);
		//memcpy(data+seedlen, &i, 4);
		
		/* Computing Hash */
		if((ret=Hash(hid, data, seedlen+4, hash))!=0) {
			free(data);
			free(hash);
			return ERR_HASH;
		}
		
		/* Appending Hash to T */ 
		memcpy(T+i*hlen, hash, hlen);
	}
	
	free(data);
	free(hash);
	
	memcpy(mask, T, masklen);
	
	return ERR_OK;
}

/* Main Functions */

int PKCS1_RSA_GenKey(PKCS1_RSA_PUBLIC_KEY *spk, PKCS1_RSA_PRIVATE_KEY *ssk, UINT mod_len)
{
	DIGIT_T *p, *q, *n, *e, *d;
	DIGIT_T Phi[MAX_DIG_LEN];
	DIGIT_T g[MAX_DIG_LEN];
	DIGIT_T t[MAX_DIG_LEN];
	UINT plen;
	UINT qlen;
	UINT prime_len;
	int ret;
		
	/* Limit checking */
	if(mod_len < MIN_RSA_MODULUS_LEN)
		return ERR_MOD_TOO_SMALL;
	if(mod_len > MAX_RSA_MODULUS_LEN)
		return ERR_MOD_TOO_LONG;
		
	/* Computing length of two primes */
	prime_len = plen = mod_len / 2;
	qlen = mod_len - plen;
	if(qlen > prime_len)
		prime_len = qlen;
		
	/* allocate memory */
	n = (DIGIT_T*)malloc(NBYTE(mod_len));
	mpSetZero(n, mod_len);
	
	e = (DIGIT_T*)malloc(NBYTE(mod_len));
	mpSetZero(e, mod_len);
	
	d = (DIGIT_T*)malloc(NBYTE(mod_len));
	mpSetZero(d, mod_len);
	
	p = (DIGIT_T*)malloc(NBYTE(plen));
	mpSetZero(p, plen);
	
	q = (DIGIT_T*)malloc(NBYTE(qlen));
	mpSetZero(q, qlen);
	
	#if defined TEST_VECT // MJ add test vectors
	/*
	TEST VECTORS: 
	https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf
	*/
		uint32_t p_num[] = {
			0xeecfae81,0xb1b9b3c9,0x08810b10,0xa1b56001,0x99eb9f44,
			0xaef4fda4,0x93b81a9e,0x3d84f632,0x124ef023,0x6e5d1e3b,
			0x7e28fae7,0xaa040a2d,0x5b252176,0x459d1f39,0x7541ba2a,
			0x58fb6599
		};

  		uint32_t q_num[] = {
			0xc97fb1f0,0x27f453f6,0x341233ea,0xaad1d935,0x3f6c42d0,
		  	0x8866b1d0,0x5a0f2035,0x028b9d86,0x9840b416,0x66b42e92,
			0xea0da3b4,0x3204b5cf,0xce335252,0x4d0416a5,0xa441e700,
			0xaf461503
		};
		
		uint32_t len = 16;

		for(int i=0; i< len ;i++){
			p[len -1 -i] = p_num[i];
			q[len -1 -i] = q_num[i];
		}


	#else 

	/* Generate p and q */
	ret = GenRsaPrime(p, plen);
	if (ret==-1) 
		return ERR_PRIME_FAILED;
	mcrypto_dump("Key Gen: prime p",(BYTE *)p, NBYTE(plen));
	
	ret = GenRsaPrime(q, qlen);
	if (ret==-1) 
		return ERR_PRIME_FAILED;
	mcrypto_dump("Key Gen: prime q",(BYTE *)q, NBYTE(qlen));
	
	#endif


	/* Compute n */
	mpMultiply(Phi, p, q, prime_len);
	mpSetEqual(n, Phi, mod_len);
	mcrypto_dump("Key Gen Modulus",(BYTE *)n, NBYTE(mod_len));
	
	/* Phi(n) = (p-1)*(q-1) */
	mpShortSub(g, p, 1, plen);
	mpShortSub(t, q, 1, qlen);
	mpMultiply(Phi, g, t, prime_len);
	mcrypto_dump("Key Gen Phi(n)=(p-1)(q-1)",(BYTE *)Phi, NBYTE(2*prime_len));
	
	do {
		#if defined TEST_VECT
		e[0] = 0x11;
		#else
		/* Generate e */
		mpMakeRandom(e, mod_len);
		
		#endif
		/* Calculate private key, d = e^-1 Mod L */
		mpModInv(d, e, Phi, mod_len);
		
		/* Check whether e*d = 1 mod Phi(n) */
		mpModMult(t, d, e, Phi, mod_len);
		
	} while(mpShortCmp(t, 1, mod_len) != 0); 
	
	mcrypto_dump("Key Gen Public Exponent e",(BYTE *)e, NBYTE(mod_len));
	mcrypto_dump("Key Gen Private Exponent d",(BYTE *)d, NBYTE(mod_len));
	
	/* Collecting data */
	spk->len = mod_len;
	spk->modulus = n;
	spk->exponent = e;
	
	ssk->len = mod_len;
	ssk->modulus = n;
	ssk->PublicExponent = e;
	ssk->exponent = d;
	ssk->p = p;
	ssk->plen = plen;
	ssk->q = q;
	ssk->qlen = qlen;
	

	return ERR_OK;
}

int PKCS1_RSAEP(PKCS1_RSA_PUBLIC_KEY *spk, DIGIT_T *m, DIGIT_T *c)
{
	/* Do RSA Encryption */
	mpModExp(c, m, spk->exponent, spk->modulus, spk->len);
	
	return ERR_OK;
}

int PKCS1_RSADP(PKCS1_RSA_PRIVATE_KEY *ssk, DIGIT_T *c, DIGIT_T *m)
{
	/* Do RSA Decryption */
	mpModExp(m, c, ssk->exponent, ssk->modulus, ssk->len);
	
	return ERR_OK;
}

int PKCS1_RSASP1(PKCS1_RSA_PRIVATE_KEY *ssk, DIGIT_T *m, DIGIT_T *s)
{
	/* Do RSA Signing */
	return PKCS1_RSADP(ssk, m, s);
}


int PKCS1_RSAVP1(PKCS1_RSA_PUBLIC_KEY *spk, DIGIT_T *s, DIGIT_T *m)
{
	/* Extract Encoded Message */
	return PKCS1_RSAEP(spk, s, m);

}

int PKCS1_EME_OAEP_ENC(PKCS1_RSA_PUBLIC_KEY *spk, UINT hid, BYTE *m, UINT mlen, BYTE *L, UINT llen, BYTE *em)
{
	/* Encoding message m of length mlen to em using OAEP */
	UINT hlen;	/* Hash Output Length in Byte */
	UINT k;		/* Encoded Message Length */
	BYTE *lHash;	/* Hash of L */
	BYTE *DB;
	BYTE *seed;
	BYTE *dbMask;
	BYTE *seedMask;
	int ret;
	
	k = NBYTE(spk->len);
	if((hlen = HashLenQuery(hid))==0)
		return ERR_UNKNOWN_HASH;
		
	/* Length checking */
	if(mlen > (k - 2*hlen - 2))
		return ERR_MSG_TOO_LONG;
	
	/* Compute Hash of L */
	mcrypto_dump("OAEP Encoding: L", L, llen);
	lHash = (BYTE *)malloc(hlen);
	if(Hash(hid, L, llen, lHash)!=0){
		return ERR_HASH;
	}
	mcrypto_dump("OAEP Encoding: Hash of L", lHash, hlen);
	
	/* Forming DB */
	DB = (BYTE *)malloc(k-hlen-1);
	memset(DB, 0x00, k-hlen-1);
	
	memcpy(DB, lHash, hlen);
	DB[k-hlen-mlen-2] = 0x01;
	memcpy(DB+k-hlen-mlen-1, m, mlen);
	mcrypto_dump("OAEP Encoding: DB", DB, k-hlen-1);
	
	/* Make a random seed */
	seed = (BYTE *)malloc(hlen);
	#if defined TEST_VECT // MJ add test vectors
	
		BYTE test_seed [] = {
			0xaa, 0xfd, 0x12, 0xf6, 0x59, 0xca, 0xe6, 0x34, 0x89, 
			0xb4, 0x79, 0xe5, 0x07, 0x6d, 0xde, 0xc2, 0xf0, 0x6c, 0xb5, 0x8f
		};

		for(int i=0; i<hlen; i++){
			seed[i] = test_seed[i];
		}
	
	#else
		GenSeed(seed, hlen);
	#endif

	mcrypto_dump("OAEP Encoding: seed", seed, hlen);
	
	/* Forming maskedDB and maskedSeed */
	dbMask = (BYTE *)malloc(k-hlen-1);
	if((ret=MGF1(hid, seed, hlen, dbMask, k-hlen-1))!=ERR_OK) {
		free(lHash);
		free(DB);
		free(seed);
		
		return ret;
	}
	mcrypto_dump("OAEP Encoding: dbMask", dbMask, k-hlen-1); 
	
	memxor(DB, DB, dbMask, k-hlen-1);
	mcrypto_dump("OAEP Encoding: maskedDB", DB, k-hlen-1);
	
	seedMask = (BYTE *)malloc(hlen);
	if((ret=MGF1(hid, DB, k-hlen-1, seedMask, hlen))!=ERR_OK) {
		free(lHash);
		free(DB);
		free(seed);
		free(seedMask);
		
		return ret;
	}

	mcrypto_dump("OAEP Encoding: seedMask", seedMask, hlen);
	
	memxor(seed, seed, seedMask, hlen);
	mcrypto_dump("OAEP Encoding: maskedSeed", seed, hlen);
	
	/* forming OAEP-encoded message */
	memset(em, 0x00, k);
	memcpy(em+1, seed, hlen);
	memcpy(em+1+hlen, DB, k-hlen-1);
	mcrypto_dump("OAEP Encoding: Encoded Message em", em, k);
	
	/* free used memory */
	free(lHash);
	free(DB);
	free(seed);
	free(dbMask);
	free(seedMask);
	
	return ERR_OK;
}

int PKCS1_RSA_OAEP_ENCRYPT(PKCS1_RSA_PUBLIC_KEY *spk, UINT hid, BYTE *m, UINT mlen, BYTE *L, UINT llen, BYTE *c)
{
	/* Encryption using RSA-OAEP */
	BYTE *em;
	int ret;
	
	mcrypto_dump("RSAOAEP Encrupt: Plaintext m", m, mlen);
	
	/* Encoding message */
	em = (BYTE *)malloc(NBYTE(spk->len));
	
	if((ret = PKCS1_EME_OAEP_ENC(spk, hid, m, mlen, L, llen, em))!=ERR_OK) {
		free(em);
		return ret;
	}

	BYTE* reversed = (BYTE *)malloc(NBYTE(spk->len));
	UINT len = NBYTE(spk->len);

	for(int i=0; i<len; i++){  // MJ for conversion to BN format
		reversed[i] = em[len -1 -i];
	}
	
	/* Do Encryption */
	ret = PKCS1_RSAEP(spk, (DIGIT_T *)reversed, (DIGIT_T *)c);
	mcrypto_dump("RSAOAEP Encrypt: Ciphertext c", c, NBYTE(spk->len));
	
	free(em);
	free(reversed);
	
	return ret;
}
	

int PKCS1_EME_OAEP_DEC(PKCS1_RSA_PRIVATE_KEY *ssk, UINT hid, BYTE *em, BYTE *L, UINT llen, BYTE *m, UINT *mlen)
{
	/* OAEP Decoding */
	UINT hlen;	/* Hash Output Length in Byte */
	UINT k;		/* Encoded Message Length */
	BYTE *lHash;	/* Hash of L */
	BYTE *DB;
	BYTE *seed;
	BYTE *maskedDB;
	BYTE *maskedSeed;
	UINT i;
	int ret;
	
	k = NBYTE(ssk->len);
	mcrypto_dump("OAEP Decoding: Encoded Message em", em, k);
	
	if(*(em)) /* fist byte of encoded message not 0x00 */
		return ERR_DECRYPTION;
	
	if((hlen = HashLenQuery(hid))==0)
		return ERR_UNKNOWN_HASH;
		
	/* Compute Hash of L */
	mcrypto_dump("OAEP Decoding: L", L, llen);
	lHash = (BYTE *)malloc(hlen);
	if((ret=Hash(hid, L, llen, lHash))!=0) {
		free(lHash);
		
		return ret;
	}
	
	mcrypto_dump("OAEP Decoding: Hash of L", lHash, hlen);
	
	/* Extracting maskedDB and maskedSeed from encoded message em */
	maskedSeed = (BYTE *)malloc(hlen);
	memcpy(maskedSeed, em+1, hlen);
	mcrypto_dump("OAEP Decoding: maskedSeed", maskedSeed, hlen);
	
	maskedDB = (BYTE *)malloc(k-hlen-1);
	memcpy(maskedDB, em+1+hlen, k-hlen-1);
	mcrypto_dump("OAEP Decoding: maskedDB", maskedDB, k-hlen-1);
	
	/* Finding seed and DB */
	seed = (BYTE *)malloc(hlen);
	if((ret=MGF1(hid, maskedDB, k-hlen-1, seed, hlen))!=ERR_OK)
	{
		free(lHash);
		free(maskedSeed);
		free(maskedDB);
		free(seed);
		
		return ret;
	}
	mcrypto_dump("OAEP Decoding: seedMask", seed, hlen);
	
	memxor(seed, seed, maskedSeed, hlen);
	mcrypto_dump("OAEP Decoding: seed", seed, hlen);
	
	DB = (BYTE *)malloc(k-hlen-1);
	if((ret=MGF1(hid, seed, hlen, DB, k-hlen-1))!=ERR_OK) {
		free(lHash);
		free(maskedSeed);
		free(maskedDB);
		free(seed);
		free(DB);
		
		return ret;
	}

	mcrypto_dump("OAEP Decoding: dbMask", DB, k-hlen-1);
	memxor(DB, DB, maskedDB, k-hlen-1);
	mcrypto_dump("OAEP Decoding: DB", DB, k-hlen-1);
	
	/* Checking whether first hlen bits of DB equals to lHash */
	if(memcmp(lHash, DB, hlen)!=0) {
		free(lHash);
		free(DB);
		free(seed);
		free(maskedDB);
		free(maskedSeed);
		
		return ERR_DECRYPTION;
	}
	
	/* Try to Extract M from DB */
	i = hlen;
	while((DB[i] == 0x00) && (DB[i] != 0x01) && (i < (k-hlen-1-1))) i++;
	
	if(i == (k-hlen-1-1)) {
		free(lHash);
		free(DB);
		free(seed);
		free(maskedDB);
		free(maskedSeed);
		
		return ERR_DECRYPTION;
	}
	
	if(DB[i] != 0x01) {
		free(lHash);
		free(DB);
		free(seed);
		free(maskedDB);
		free(maskedSeed);
		
		return ERR_DECRYPTION;
	}	
	
	*mlen = k-hlen-1-1 - (i+1) + 1; /* starting after 0x01 byte to the end of DB */
	memcpy(m, DB+i+1, *mlen);
	mcrypto_dump("OAEP Decoding: Plaintext m", m, *mlen);
	
	free(lHash);
	free(DB);
	free(seed);
	free(maskedDB);
	free(maskedSeed);
		
	return ERR_OK;
}

int PKCS1_RSA_OAEP_DECRYPT(PKCS1_RSA_PRIVATE_KEY *ssk, UINT hid, BYTE *c, BYTE *L, UINT llen, BYTE *m, UINT *mlen)
{
	/* RSA-OAEP Decryption */
	BYTE *em;
	int ret;
	UINT hlen;
	
	if((hlen = HashLenQuery(hid)) == 0)
		return ERR_UNKNOWN_HASH;
	
	/* Length checking */
	if(NBYTE(ssk->len)<(2*hlen+2))
		return ERR_DECRYPTION;
	
	mcrypto_dump("RSAOAEP Decrypt: Ciphertext", c, NBYTE(ssk->len));
	
	/* Do RSA Decryption */
	em = (BYTE *)malloc(NBYTE(ssk->len));
	ret = PKCS1_RSADP(ssk, (DIGIT_T *)c, (DIGIT_T *)em);
	
	BYTE* reversed = (BYTE *)malloc(NBYTE(ssk->len));
	UINT len = NBYTE(ssk->len);

	for(int i=0;i<len; i++){
		reversed[i] = em[len - 1 -i];
	}

	mcrypto_dump("RSAOAEP Decrypt: OAEP-Encoded Message (After Decryption)",(BYTE *)reversed, NBYTE(ssk->len));
	
	/* Decoding Message */
	ret = PKCS1_EME_OAEP_DEC(ssk, hid, reversed, L, llen, m, mlen);
	
	free(em); 
	free(reversed);
	
	return ret;
}

int PKCS1_RSASSA_PSS_SIGN(PKCS1_RSA_PRIVATE_KEY *ssk, UINT hid, BYTE *m, UINT mlen, UINT slen, BYTE *s)
{
	/* PKCS1 #1 RSA Signature Generation Using PSS Encoding */
	BYTE *em;
	int ret;
	
	/* Preparing encoded message */
	em = (BYTE *)malloc(NBYTE(ssk->len));
	
	/* PSS Encoding */
	if((ret=PKCS1_EMSA_PSS_ENCODE(hid, m, mlen, slen, em, NBYTE(ssk->len)))!=ERR_OK) {
		free(em);
		return ret;
	}
	
	/* Signing */
	ret = PKCS1_RSASP1(ssk, (DIGIT_T*)em, (DIGIT_T*)s);
	mcrypto_dump("Signature",(BYTE *)s, NBYTE(ssk->len));
	
	free(em);
	
	return ret;
}

int PKCS1_RSASSA_PSS_VERIFY(PKCS1_RSA_PUBLIC_KEY *spk, UINT hid, BYTE *m, UINT mlen, UINT slen, BYTE *s)
{
	/* PKCS #1 RSA Signature Verification Using PSS Encoding */
	BYTE *em;
	int ret;
	
	mcrypto_dump("Signature", s, NBYTE(spk->len));

	/* Extracting encoded message */
	em = (BYTE *)malloc(NBYTE(spk->len));
	
	if((ret = PKCS1_RSAVP1(spk, (DIGIT_T *)s, (DIGIT_T *)em))!=ERR_OK) {
		free(em);
		return ret;
	}
	mcrypto_dump("PSS-Encoded Message (Before Verificaton)",(BYTE *)em, NBYTE(spk->len));
	
	/* Verify encoded message */
	ret = PKCS1_EMSA_PSS_VERIFY(hid, m, mlen, slen, em, NBYTE(spk->len));
	
	free(em);
	
	if(ret == ERR_PSS_CONSISTENT)
		return ERR_VALID_SIGNATURE;
		
	return ERR_INVALID_SIGNATURE;
}

int PKCS1_EMSA_PSS_ENCODE(UINT hid, BYTE *m, UINT mlen, UINT slen, BYTE *em, UINT emlen)
{
	/* PSS Encoding */
	UINT hlen;	/* Length of Hash Output */
	BYTE *H;	/* Hash of m */
	BYTE *salt;
	BYTE *M;
	BYTE *DB;
	BYTE *maskedDB;
	int ret;
	
	if((hlen = HashLenQuery(hid)) == 0)
		return ERR_UNKNOWN_HASH;
	
	/* Computing Hash of m */
	mcrypto_dump("PSS Encoding: Message", m, mlen);
	H = (BYTE *)malloc(hlen);
	if((ret = Hash(hid, m, mlen, H))!=0) {
		free(H);
		
		return ret;
	}

	mcrypto_dump("PSS Encoding: Hashed Message", H, hlen);
	
	/* Length checking */
	if(emlen<(hlen+slen+2)) {
		free(H);
		return ERR_PSS_ENCODING;
	}
	
	/* Generating salt and constructing M */
	salt = (BYTE *)malloc(slen);
	GenSeed(salt, slen);
	mcrypto_dump("PSS Encoding: Salt", salt, slen);
	
	M = (BYTE *)malloc(8+hlen+slen);
	memset(M, 0x00, 8+hlen+slen);
	memcpy(M+8, H, hlen);
	memcpy(M+8+hlen, salt, slen);
	mcrypto_dump("PSS Encoding: Message to be encoded", M, 8+hlen+slen);
	
	/* Constructing DB */
	if((ret = Hash(hid, M, 8+hlen+slen, H))!=0) {
		free(H);
		free(M);
		free(salt);
		
		return ret;
	}
	mcrypto_dump("PSS Encoding: Hash of Message to be encoded", H, hlen);
	
	DB = (BYTE *)malloc(emlen-hlen-1);
	memset(DB, 0x00, emlen-hlen-1);
	DB[emlen-slen-hlen-2] = 0x01;
	memcpy(DB+emlen-slen-hlen-1, salt, slen);
	mcrypto_dump("PSS Encoding: DB", DB, emlen-hlen-1);
	
	/* Computing maskedDB */
	maskedDB = (BYTE *)malloc(emlen-hlen-1);
	if((ret=MGF1(hid, H, hlen, maskedDB, emlen-hlen-1))!=ERR_OK) {
		free(H);
		free(M);
		free(salt);
		free(maskedDB);
		free(DB);
		
		return ret;
	}

	mcrypto_dump("PSS Encoding: dbMask", maskedDB, emlen-hlen-1);
	
	memxor(maskedDB, maskedDB, DB, emlen-hlen-1);
	mcrypto_dump("PSS Encoding: maskedDB", maskedDB, emlen-hlen-1);
	
	/* Constructing encoded message, em */
	memcpy(em, maskedDB, emlen-hlen-1);
	memcpy(em+emlen-hlen-1, H, hlen);
	em[emlen-1] = 0xbc;
	mcrypto_dump("PSS Encoding: Encoded Message", em, emlen);
	
	return ERR_OK;
}

int PKCS1_EMSA_PSS_VERIFY(UINT hid, BYTE *m, UINT mlen, UINT slen, BYTE *em, UINT emlen)
{
	/* PSS Verification */
	UINT hlen;	/* Length of Hash Output */
	BYTE *H;	/* Hash of m */
	BYTE *M;
	BYTE *mHash;
	BYTE *DB;
	BYTE *maskedDB;
	int ret;
	
	if((hlen = HashLenQuery(hid)) == 0)
		return ERR_UNKNOWN_HASH;
	
	/* Computing Hash of m */
	mcrypto_dump("PSS Verify: Message", m, mlen);
	mHash = (BYTE *)malloc(hlen);
	if((ret = Hash(hid, m, mlen, mHash))!=0) {
		free(mHash);
		return ret;
	}
	
	mcrypto_dump("PSS Verify: Hash of Message", mHash, hlen);
	
	/* Length checking */
	mcrypto_dump("PSS Verify: Encoded Message", em, emlen);
	
	if(emlen<(hlen+slen+2)) {
		free(mHash);
		return ERR_PSS_INCONSISTENT;
	}
	
	/* Verification */
	if(em[emlen-1]!=0xbc) {
		free(mHash);
		return ERR_PSS_INCONSISTENT;
	}
	
	/* Extracting maskedDB and H */
	maskedDB = (BYTE *)malloc(emlen-hlen-1);
	memcpy(maskedDB, em, emlen-hlen-1);
	mcrypto_dump("PSS Verify: maskedDB", maskedDB, emlen-hlen-1);
	
	H = (BYTE *)malloc(hlen);
	memcpy(H, em+emlen-hlen-1, hlen);
	mcrypto_dump("PSS Verify: H", H, hlen);
	
	/* Computing DB */ 
	DB = (BYTE *)malloc(emlen-hlen-1);
	if((ret=MGF1(hid, H, hlen, DB, emlen-hlen-1))!=ERR_OK) {
		free(H);
		free(mHash);
		free(maskedDB);
		free(DB);
		
		return ret;
	}
	mcrypto_dump("PSS Verify: dbMask", DB, emlen-hlen-1);
	
	memxor(DB, DB, maskedDB, emlen-hlen-1);
	mcrypto_dump("PSS Verify: DB", DB, emlen-hlen-1);
	
	if(DB[emlen-slen-hlen-2]!=0x01) {
		free(H);
		free(mHash);
		free(maskedDB);
		free(DB);
		
		return ERR_PSS_INCONSISTENT;
	}
	
	M = (BYTE *)malloc(8+hlen+slen);
	memset(M, 0x00, 8+hlen+slen);
	memcpy(M+8, mHash, hlen);
	memcpy(M+8+hlen, DB+emlen-slen-hlen-1, slen);
	mcrypto_dump("PSS Verify: Message to encoded", M, 8+hlen+slen);
	
	if((ret = Hash(hid, M, 8+hlen+slen, mHash))!=0) {
		free(H);
		free(mHash);
		free(maskedDB);
		free(DB);
		free(M);
		
		return ret;
	}
	
	mcrypto_dump("PSS Verify: Hash of Message to encoded", mHash, hlen);
	
	if(memcmp(H, mHash, hlen)!=0) 
		return ERR_PSS_INCONSISTENT;
		
	return ERR_PSS_CONSISTENT;
}

void errmsg(int err)
{
	switch(err) {
	case ERR_OK:			printf("Job Done Successfully!!!\n"); break;
	case ERR_MOD_TOO_SMALL:		printf("Wow!!! Modulus Length Too Short.\n"); break;
	case ERR_MOD_TOO_LONG:		printf("Sorry!!! Modulus Length Too Long.\n"); break;
	case ERR_PRIME_FAILED:		printf("Failed To Generate A Prime. Try It Again.\n"); break;
	case ERR_MSG_TOO_LONG:		printf("Sorry!!! Message Too Long.\n"); break;
	case ERR_LABEL_TOO_LONG:	printf("Sorry!!! OAEP Label Too Long\n"); break;
	case ERR_DECRYPTION:		printf("Sorry!!! Decryption Error.\n"); break;
	case ERR_UNKNOWN_HASH:		printf("Sorry!!! Hash Function Not Available.\n"); break;
	case ERR_VALID_SIGNATURE:	printf("Good!!! Signature Is Valid.\n"); break;	
	case ERR_INVALID_SIGNATURE:	printf("Sorry!!! Signature Is Invalid.\n"); break;
	case ERR_PSS_CONSISTENT:	printf("Good!!! PSS-Encoded Message Is Consistent.\n"); break;
	case ERR_PSS_INCONSISTENT:	printf("Sorry!!! PSS-Encoded Message Is Inconsistent.\n"); break;
	case ERR_PSS_ENCODING:		printf("Sorry!!! PSS Encoding Error\n"); break;
	case ERR_HASH:			printf("Sorry!!! Hash Function Error. Maybe Hash Input Limit Exceeded\n"); break;
	default: 			printf("Unkown Error!!!\n"); break;
	}
}

int LoadPublicKey(char *fname, PKCS1_RSA_PUBLIC_KEY *spk)
{
	/* Load keys from files */
	char s[5][PKCS1_MAX_LINE_LEN];	
	FILE *f;
	UINT i;
	UINT len;
	
	f = fopen(fname, "r");
	if(f == NULL)
		return -1;
	
	memset(s, 0x00, PKCS1_MAX_LINE_LEN*5);	
	/* reading data */
	for(i=0;i<5;i++)
	{
		if(feof(f))
		{
			fclose(f);
			return -1;
		}
		fgets(s[i], PKCS1_MAX_LINE_LEN, f);
		
		/* ignore newline charater */		
		s[i][strlen(s[i])-1] = '\0';
	}
	fclose(f);
	
	/* Decoding data */
	spk->len = (UINT)atoi(s[1]);
	
	if((spk->modulus = mpBase64Decode(&len, s[2]))==NULL)
		return -1; 
	if((spk->exponent = mpBase64Decode(&len, s[3]))==NULL)
		return -1; 
	return 0;
}

int LoadPrivateKey(char *fname, PKCS1_RSA_PRIVATE_KEY *ssk)
{
	/* Load keys from files */
	char s[6][PKCS1_MAX_LINE_LEN];
	FILE *f;
	UINT i;
	UINT len;
	
	f = fopen(fname, "r");
	if(f == NULL)
		return -1;
		
	memset(s, 0x00, PKCS1_MAX_LINE_LEN*6);	
	
	/* reading data */
	for(i=0;i<5;i++)
	{
		if(feof(f))
		{
			fclose(f);
			return -1;
		}
		fgets(s[i], PKCS1_MAX_LINE_LEN, f);
		s[i][strlen(s[i])-1] = '\0';
	}
	fclose(f);
	
	ssk->len = (UINT)atoi(s[1]);
	
	if((ssk->modulus = mpBase64Decode(&len, s[2]))==NULL)
		return -1; 
	if((ssk->PublicExponent = mpBase64Decode(&len, s[3]))==NULL)
		return -1; 
	if((ssk->exponent = mpBase64Decode(&len, s[4]))==NULL)
		return -1; 	
	
	return 0;
}


