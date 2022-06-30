# Filename: Makefile
# Author: Martin Janitor
# Bachelor thesis: RSA with OAEP padding
# Date: 05.06.2022
# Version: 1.3


CC=gcc
CFLAGS= -Wall -Os -O3 -Wextra -g

SOURCE = test01.c ../EXTENSIONS/ext_sha.c ../SHA_1/sha1.c ../SHA_256/sha256.c ../SHA_512/sha512.c

test01:
	$(CC) $(CFLAGS) $(SOURCE) -o test01

clean:
	rm -rf test01