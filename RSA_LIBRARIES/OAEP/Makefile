# Filename: Makefile
# Author: Martin Janitor
# Bachelor thesis: RSA with OAEP padding
# Date: 05.06.2022
# Version: 1.3

CC=gcc
CFLAGS= -Wall -Os -O3 -Wextra -g

SOURCE = test01.c oaep.c ../HASH/EXTENSIONS/ext_sha.c ../HASH/SHA_1/sha1.c ../HASH/SHA_256/sha256.c ../HASH/SHA_512/sha512.c 

test01:
	$(CC) $(CFLAGS) $(SOURCE) -o test01

clean:
	rm -rf test01