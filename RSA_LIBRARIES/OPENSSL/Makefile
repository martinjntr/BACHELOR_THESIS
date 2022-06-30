# Filename: Makefile
# Author: Martin Janitor
# Bachelor thesis: RSA with OAEP padding
# Date: 24.05.2022
# Version: 1.2

CC=gcc
CFLAGS=  -O2 -Wall -g

OpenSSL_PATH= C:/OpenSSL-Win64


test01:
	$(CC) $(CFLAGS) test01.c -L $(OpenSSL_PATH)/lib -lcrypto -I $(OpenSSL_PATH)/include -o test01

test02:
	$(CC) $(CFLAGS) test02.c -L $(OpenSSL_PATH)/lib -lcrypto -I $(OpenSSL_PATH)/include -o test02

test05:
	$(CC) $(CFLAGS) test05.c -L $(OpenSSL_PATH)/lib -lcrypto -I $(OpenSSL_PATH)/include -o test05

test06:
	$(CC) $(CFLAGS) test06.c -L $(OpenSSL_PATH)/lib -lcrypto -I $(OpenSSL_PATH)/include -o test06

clean:
	rm -rf test01 test02 test05

