# Filename: Makefile
# Author: Martin Janitor
# Bachelor thesis: RSA with OAEP padding
# Date: 24.05.2022
# Version: 1.2


DIR_ROOT = ../../MCRYPTO/
DIR_MAIN = $(DIR_ROOT)src/

CC = gcc
CFLAGS = -g -I $(DIR_ROOT)include -I ../


# choose method for mp multplication, use -DMCRYPTO_FFT_MUL for FFT multiplication method
MP_MUL_METHOD_FLAG = -DMCRYPTO_SCHOOL_BOOK -g
# choose method for modulo reduction, use -DMCRYPTO_BARRET for Barret reduction method
MP_MODULO_METHOD_FLAG = -DMCRYPTO_TRIVIAL_DIVISION 
# enable/disbale use of assembly for certain mp low-level routines
USE_ASM_FLAG = -DMCRYPTO_USE_ASM=0
# optimization flags
OPT_FLAGS = -O2 -m64

DEBUG_INF = -DMCRYPTO_DEBUG -DTEST_VECT

CFLAGS_1 = $(CFLAGS) -D__MCRYPTO__  $(MP_MUL_METHOD_FLAG) $(MP_MODULO_METHOD_FLAG)\
 $(USE_ASM_FLAG) $(OPT_FLAGS) -pipe -fomit-frame-pointer

SOURCES = $(DIR_MAIN)*.c ../extensions_mcrypto.c 


test01:	$(SOURCES)
	$(CC)	test01.c $(CFLAGS_1) 	-DMOD_LEN=1024	$(SOURCES) 	-o test01

test02:	$(SOURCES)
	$(CC)	test02.c $(CFLAGS_1) 	-DMOD_LEN=1024	$(SOURCES) 	-o test02

test03:	$(SOURCES)
	$(CC)	test02.c $(CFLAGS_1) 	-DMOD_LEN=2048	$(SOURCES) 	-o test03

test04:	$(SOURCES)
	$(CC)	test02.c $(CFLAGS_1)	-DMOD_LEN=4096	$(SOURCES) 	-o test04

test05:	$(SOURCES)
	$(CC)	test05.c $(CFLAGS_1)	-DMOD_LEN=4096	$(SOURCES) 	-o test05

test06:	$(SOURCES)
	$(CC)	test06.c $(CFLAGS_1)	-DMOD_LEN=1024	$(SOURCES) 	-o test06

test_vect:	$(SOURCES)
	$(CC)	test_vect.c $(CFLAGS_1)	$(DEBUG_INF)	-DMOD_LEN=4096	$(SOURCES) 	-o test05
