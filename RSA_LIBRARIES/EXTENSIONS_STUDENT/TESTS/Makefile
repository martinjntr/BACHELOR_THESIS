DIR_ROOT = ../../
DIR_OAEP = $(DIR_ROOT)OAEP/
DIR_RSA =  $(DIR_ROOT)STUDENT/src/
DIR_SHA_1 = $(DIR_ROOT)HASH/SHA_1/
DIR_SHA_256 = $(DIR_ROOT)HASH/SHA_256/
DIR_SHA_512 = $(DIR_ROOT)HASH/SHA_512/
DIR_SHA_EXT = $(DIR_ROOT)HASH/EXTENSIONS/
DIR_EXT = ../src/


# Filename: Makefile
# Author: Martin Janitor
# Bachelor thesis: RSA with OAEP padding
# Date: 24.05.2022
# Version: 1.2

CC = gcc
CFLAGS = -g -Wall 
INCLUDE	=	-I$(DIR_EXT)include

COMP_8 = -DBIT8
COMP_32 = -DBIT32
TEST_VECT = -DTEST_VECT
PRINT_TEST_VECT = -DPRINT

SOURCE_OAEP = $(DIR_OAEP)oaep.c
SOURCE_BIGNUM = $(DIR_RSA)bignum.c
SOURCE_SHA_1 = $(DIR_SHA_1)sha1.c
SOURCE_SHA_256 = $(DIR_SHA_256)sha256.c
SOURCE_SHA_512 = $(DIR_SHA_512)sha512.c
SOURCE_RSA_EXP = $(DIR_EXT)ext_rsa.c
SOURCE_BIGNUM_EXP = $(DIR_EXT)ext_bignum.c
SOURCE_SHA_EXT = $(DIR_SHA_EXT)ext_sha.c
SOURCE_FILE_EXT = $(DIR_EXT)ext_file.c


ALL_SOURCE = $(SOURCE_SHA_1) $(SOURCE_SHA_256) $(SOURCE_FILE_EXT) $(SOURCE_SHA_512) $(SOURCE_OAEP) $(SOURCE_BIGNUM)	$(SOURCE_RSA_EXP) $(SOURCE_BIGNUM_EXP)	$(SOURCE_SHA_EXT)

test01:	$(ALL_SOURCE)
	$(CC)	$(COMP_8) test01.c $(CFLAGS) 	$(ALL_SOURCE) 	-o test01
	
test02:	$(ALL_SOURCE)
	$(CC)	$(COMP_8) test02.c $(CFLAGS) 	$(ALL_SOURCE) 	-o test02

test05: $(ALL_SOURCE)
	$(CC)	$(COMP_32) test05.c $(CFLAGS)	$(ALL_SOURCE) 	-o test05

test06: $(ALL_SOURCE)
	$(CC)	$(COMP_8) test06.c $(CFLAGS)	$(ALL_SOURCE) 	-o test06

test07: $(ALL_SOURCE)
	$(CC)	$(COMP_32) test07.c $(CFLAGS)	$(ALL_SOURCE) 	-o test07

test08: $(ALL_SOURCE)
	$(CC)	$(COMP_8) test08.c $(CFLAGS)	$(ALL_SOURCE) 	-o test08

test09: $(ALL_SOURCE)
	$(CC)	$(COMP_32) test09.c $(CFLAGS)	$(ALL_SOURCE) 	-o test09

test_vect: $(ALL_SOURCE)
	$(CC)	$(COMP_8) test_vect.c $(CFLAGS) 	$(TEST_VECT) $(PRINT_TEST_VECT)	$(ALL_SOURCE) 	-o test_vect
	
clean:	
	rm -rf test01 test02 test05 test06 test07 test_vect
