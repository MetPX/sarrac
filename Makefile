.PHONY: all core test lib install clean format check

CC		= gcc
CFLAGS		= -fPIC -ftest-coverage -fstack-check -std=gnu99 -Wall -g -D_GNU_SOURCE
INCLUDES	= -Iinclude/
LIBS		= -lrabbitmq -lcrypto

HEADERS		:= $(wildcard include/*.h)

CORE_SOURCES	:= $(wildcard src/core/*.c)
LIB_SOURCES	:= $(wildcard src/lib/*.c)

CORE_OBJECTS	:= $(CORE_SOURCES:src/core/%.c=obj/core/%.o)
LIB_OBJECTS	:= $(LIB_SOURCES:src/lib/%.c=obj/lib/%.o) 

# build all components
all: lib core
	@rm -rf obj/

# build core
core: lib bin/sr_cpost bin/sr_cpump

bin/sr_cpost: $(HEADERS) bin/libsarra.so obj/core/sr_cpost.o
	@mkdir -p bin/
	$(CC) $(CFLAGS) obj/core/sr_cpost.o bin/libsarra.so -o $@ $(LIBS)

bin/sr_cpump: $(HEADERS) bin/libsarra.so obj/core/sr_cpump.o
	@mkdir -p bin/
	$(CC) $(CFLAGS) obj/core/sr_cpump.o bin/libsarra.so -o $@ $(LIBS)

obj/core/%.o: src/core/%.c
	@mkdir -p obj/core/
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@ 

# build libs
lib: bin/libsarra.so bin/libsrshim.so

bin/libsarra.so: $(HEADERS) $(LIB_OBJECTS)
	@mkdir -p bin/
	$(CC) $(CFLAGS) -shared $(LIB_OBJECTS) -o $@ $(LIBS)

bin/libsrshim.so: $(HEADERS) bin/libsarra.so obj/lib/libsrshim.o
	@mkdir -p bin/
	$(CC) $(CFLAGS) -shared obj/lib/libsrshim.o bin/libsarra.so -o $@ $(LIBS)

obj/lib/%.o: src/lib/%.c
	@mkdir -p obj/lib/
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@ 
	
# build tests
test:

# install application on system
install:

# remove bin/ and obj/
clean:
	@rm -rf bin/

# set code format
format:
	@indent -linux -l100 *.c *.h
	@rm *.c~ *.h~

# run test suite
check:
