# Change your compiler settings here

# Clang seems to produce faster code
#CCPP = g++
#CC = gcc
#OPTFLAGS = -O3 -fomit-frame-pointer -funroll-loops
CCPP = clang++ -m64
CC = clang -m64
OPTFLAGS = -O3
DBGFLAGS = -g -O0 -DDEBUG
CFLAGS = -Wall -fstrict-aliasing -I.
LIBNAME = libtabby.a


# Object files

tabby_o = tabby.o SecureErase.o SecureEqual.o lyra.o sponge.o snowshoe.o \
		  Clock.o EndianNeutral.o blake2b-ref.o chacha.o chacha_blocks_ref.o

# Release target (default)

release : CFLAGS += $(OPTFLAGS)
release : library


# Debug target

debug : CFLAGS += $(DBGFLAGS)
debug : LIBNAME = libtabby_debug.a
debug : library


# Library (internal) target; use release or debug

library : $(tabby_o)
	ar rcs $(LIBNAME) $(tabby_o)


# Shared objects

Clock.o : Clock.cpp
	$(CCPP) $(CFLAGS) -c Clock.cpp

SecureErase.o : SecureErase.cpp
	$(CCPP) $(CFLAGS) -c SecureErase.cpp

SecureEqual.o : SecureEqual.cpp
	$(CCPP) $(CFLAGS) -c SecureEqual.cpp

EndianNeutral.o : EndianNeutral.cpp
	$(CCPP) $(CFLAGS) -c EndianNeutral.cpp


# Lyra objects

lyra.o : lyra.c
	$(CC) $(CFLAGS) -c lyra.c

sponge.o : sponge.c
	$(CC) $(CFLAGS) -c sponge.c


# Snowshoe objects

snowshoe.o : snowshoe.cpp
	$(CCPP) $(CFLAGS) -c snowshoe.cpp


# BLAKE2 objects

blake2b-ref.o : blake2b-ref.c
	$(CC) $(CFLAGS) -c blake2b-ref.c


# ChaCha objects

chacha.o : chacha.c
	$(CC) $(CFLAGS) -c chacha.c

chacha_blocks_ref.o : chacha_blocks_ref.c
	$(CC) $(CFLAGS) -c chacha_blocks_ref.c


# Tabby objects

tabby.o : tabby.cpp
	$(CCPP) $(CFLAGS) -c tabby.cpp


# Cleanup

.PHONY : clean

clean :
	-rm libtabby.a *.o

