# Change your compiler settings here

# Clang seems to produce faster code
#CCPP = g++
#CC = gcc
#OPTFLAGS = -O3 -fomit-frame-pointer -funroll-loops
CCPP = clang++ -m64
CC = clang -m64
OPTFLAGS = -O3
DBGFLAGS = -g -O0 -DDEBUG
CFLAGS = -Wall -fstrict-aliasing -I./blake2/sse -I./libcat -I./include \
		 -I./snowshoe/include -I./cymric/include -I./lyra
LIBNAME = bin/libtabby.a
LIBS = -lsnowshoe -lcymric


# Object files

shared_test_o = Clock.o

tabby_o = tabby.o blake2b.o SecureErase.o SecureEqual.o

tabby_test_o = tabby_test.o $(shared_test_o)


# Release target (default)

release : CFLAGS += $(OPTFLAGS)
release : library


# Debug target

debug : CFLAGS += $(DBGFLAGS)
debug : LIBNAME = libtabby_debug.a
debug : library


# Library.ARM target

library.arm : CCPP = /Volumes/casedisk/prefix/bin/arm-unknown-eabi-g++
library.arm : CPLUS_INCLUDE_PATH = /Volumes/casedisk/prefix/arm-unknown-eabi/include
library.arm : CC = /Volumes/casedisk/prefix/bin/arm-unknown-eabi-gcc
library.arm : C_INCLUDE_PATH = /Volumes/casedisk/prefix/arm-unknown-eabi/include
library.arm : library


# Library target

library : CFLAGS += $(OPTFLAGS)
library : $(tabby_o)
	ar rcs $(LIBNAME) $(tabby_o)


# tester executables

test : CFLAGS += -DUNIT_TEST $(OPTFLAGS)
test : clean $(tabby_test_o) library
	$(CCPP) $(tabby_test_o) $(LIBS) -L./bin -ltabby -L./snowshoe/bin -L./cymric/bin -o test
	./test


# Shared objects

Clock.o : libcat/Clock.cpp
	$(CCPP) $(CFLAGS) -c libcat/Clock.cpp

SecureErase.o : libcat/SecureErase.cpp
	$(CCPP) $(CFLAGS) -c libcat/SecureErase.cpp

SecureEqual.o : libcat/SecureEqual.cpp
	$(CCPP) $(CFLAGS) -c libcat/SecureEqual.cpp


# Library objects

tabby.o : src/tabby.cpp
	$(CCPP) $(CFLAGS) -c src/tabby.cpp

blake2b.o : blake2/sse/blake2b.c
	$(CC) $(CFLAGS) -c blake2/sse/blake2b.c

lyra.o : lyra/lyra.c
	$(CC) $(CFLAGS) -c lyra/lyra.c

sponge.o : lyra/sponge.c
	$(CC) $(CFLAGS) -c lyra/sponge.c


# Executable objects

tabby_test.o : tests/tabby_test.cpp
	$(CCPP) $(CFLAGS) -c tests/tabby_test.cpp


# Cleanup

.PHONY : clean

clean :
	git submodule update --init
	-rm test libtabby.a $(shared_test_o) $(tabby_test_o) $(tabby_o)

