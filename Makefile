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
LIBS = -L./snowshoe/bin -lsnowshoe -L./cymric/bin -lcymric


# Object files

shared_test_o = Clock.o

tabby_o = tabby.o blake2b.o SecureErase.o SecureEqual.o lyra.o sponge.o

tabby_test_o = tabby_test.o $(shared_test_o)


# Release target (default)

release : CFLAGS += $(OPTFLAGS)
release :
	cd cymric; make release
	cd snowshoe; make release
release : library


# Debug target

debug : CFLAGS += $(DBGFLAGS)
debug : LIBNAME = libtabby_debug.a
debug : library


# Library target

library : CFLAGS += $(OPTFLAGS)
library : $(tabby_o)
	ar rcs $(LIBNAME) $(tabby_o)


# tester executables

test : CFLAGS += -DUNIT_TEST $(OPTFLAGS)
test : clean $(tabby_test_o) release
	$(CCPP) $(tabby_test_o) -L./bin -ltabby $(LIBS) -o test
	./test


# tester executables for mobile version

test-mobile : CFLAGS += -DUNIT_TEST $(OPTFLAGS)
test-mobile : clean $(tabby_test_o)
	$(CCPP) $(tabby_test_o) -L./tabby-mobile -ltabby -o test
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
	git submodule update --init --recursive
	-rm test bin/libtabby.a $(shared_test_o) $(tabby_test_o) $(tabby_o)
	cd cymric; make clean
	cd snowshoe; make clean

