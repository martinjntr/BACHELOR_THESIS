# Filename: Makefile
# Author: Martin Janitor
# Bachelor thesis: RSA with OAEP padding
# Date: 24.05.2022
# Version: 1.2


DIR_ROOT = ../../
DIR_OAEP = $(DIR_ROOT)OAEP/
DIR_RSA =  $(DIR_ROOT)KOKKE/
DIR_HASH = $(DIR_ROOT)HASH/
DIR_SHA_1 = $(DIR_HASH)SHA_1/
DIR_SHA_256 = $(DIR_HASH)SHA_256/
DIR_SHA_512 = $(DIR_HASH)SHA_512/
DIR_SHA_EXT = $(DIR_HASH)EXTENSIONS/


CC = gcc
CFLAGS = -Wall -g -O3 -I../include

# MACRO FOR PRINTING REULTS WITH USING TEST VECTORS,
# AVAILABLE FOR test: test_vect
TEST_VECTOR_PRINT = -DTEST_VECT -DPRINT 

SOURCE_RSA = $(DIR_RSA)bn.c
SOURCE_OAEP = $(DIR_OAEP)oaep.c
SOURCE_SHA_EXT = $(DIR_SHA_EXT)ext_sha.c
SOURCE_SHA_1 = $(DIR_SHA_1)sha1.c
SOURCE_SHA_256 = $(DIR_SHA_256)sha256.c
SOURCE_SHA_512 = $(DIR_SHA_512)sha512.c
SOURCE_FILE_EXT = ../src/ext_file.c
SOURCE_RSA_EXT = ../src/ext_rsa.c

ALL_SOURCE = $(SOURCE_SHA_1) $(SOURCE_SHA_256) $(SOURCE_SHA_512) $(SOURCE_OAEP) $(SOURCE_RSA)  $(SOURCE_EXT)\
$(SOURCE_SHA_EXT) $(SOURCE_FILE_EXT) $(SOURCE_RSA_EXT)

test01:	$(ALL_SOURCE)
	$(CC)	test01.c -DMOD_LEN=1024 $(ALL_SOURCE) $(CFLAGS) -o test01

# 1024 bit RSA
test02:	$(ALL_SOURCE)
	$(CC)	test02.c  $(ALL_SOURCE) -DMOD_LEN=1024	$(CFLAGS) -o test02 

# 2048 bit RSA
test03:	$(ALL_SOURCE)
	$(CC)	test02.c  $(ALL_SOURCE) -DMOD_LEN=2048	$(CFLAGS) -o test03

# 4096 bit RSA
test04:	$(ALL_SOURCE)
	$(CC)	test02.c  $(ALL_SOURCE) -DMOD_LEN=4096	$(CFLAGS) -o test04

test_vect:	$(ALL_SOURCE)
	$(CC)	test_vect.c  -DMOD_LEN=1024 $(ALL_SOURCE) $(TEST_VECTOR_PRINT)	$(CFLAGS) -o test_vect

clean:	
	rm -rf test01 test02 test03 test04 test05 test06 test_vect
