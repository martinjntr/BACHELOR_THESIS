# About Project
In this project I modified existing cryptographic libraries which contains implmentation RSA algoritm and OAEP padding scheme. Primarily I used the C programming language.


## Cryptographic libraries RSA + OAEP
I found some implementations on internet which I modified and which I expanded based on the required properties.

Some libraries don`t contains implementation OAEP therefore, I searched for the OAEP implementation and added it to the libraries.

I found OAEP implementation which I exapnd for choosing more hash functions. Used hash function in OAEP implementation: SHA-1, SHA-256, SHA-512.

In conclusion, I would like to thank the authors of the libraries :)

## Libraries

STUDENT-> https://github.com/junwei-wang/biginteger
MCRYPTO-> https://code.google.com/archive/p/libmcrypto/downloads
KOKKE -> https://github.com/kokke/tiny-bignum-c
OpenSSL -> https://www.openssl.org/source/

---

OAEP-> https://github.com/Rupan/rsa

---

HASH-> SHA-1, SHA-256: https://github.com/B-Con/crypto-algorithms
 &nbsp;  &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;SHA-512: https://github.com/orlp/ed25519


## DOCUMENTATIONS
In project I created documenatation for cryptographic libraries which is written in Slovak language.


## TEST and Compilations
Every libraray contains subfolder TESTS which contains some examples and makefile for compilation. Libraries are usable for both Linux and Windows operating system.

**Compilation:** **make**[number of test] for example: **make** test01
