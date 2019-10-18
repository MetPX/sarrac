.PHONY: all app lib test install clean format check

### COMPILATION FLAGS ###
CC		= gcc
CLIBS		= -lrabbitmq -lcrypto
CFLAGS		= -fPIC -ftest-coverage -fstack-check -std=gnu99 -Wall -g -D_GNU_SOURCE
INCLUDES	= -Iinclude/

### FILES & PARAMETERS ##
SR_VERSION	:= $(shell head -1 debian/changelog | cut -d'(' -f2 | cut -d')' -f1)
SO_V		:= 1
SO_VXX		:= $(SO_V).0.0
HEADERS		:= $(wildcard include/*.h)

APP_SDIR	:= src/app
LIB_SDIR	:= src/lib
APP_SOURCES	:= $(wildcard src/app/*.c)
LIB_SOURCES	:= $(wildcard src/lib/*.c)

APP_ODIR	:= obj/app
LIB_ODIR	:= obj/lib
APP_OBJECTS	:= $(APP_SOURCES:src/app/%.c=obj/app/%.o)
LIB_OBJECTS	:= $(LIB_SOURCES:src/lib/%.c=obj/lib/%.o) 

LIBSARRA	:= bin/libsarra.so
LIBSARRA_SO_V	:= $(LIBSARRA).$(SO_V)
LIBSARRA_SO_VXX	:= $(LIBSARRA).$(SO_VXX)
LIBSARRA_LINK	:= -lsarra -Wl,-rpath,$(CURDIR)/bin -L$(CURDIR)/bin

LIBSHIM		:= bin/libsrshim.so
LIBSHIM_SO_V	:= $(LIBSHIM).$(SO_V)
LIBSHIM_SO_VXX	:= $(LIBSHIM).$(SO_VXX)

# build all components
all: include/sr_version.h lib app
	@echo "...xD"

# version management
include/sr_version.h: debian/changelog
	@echo "#define __sarra_version__ \"$(SR_VERSION)\"" > $@

# build apps
app: lib bin/sr_cpost bin/sr_cpump

bin/sr_cpost: $(APP_ODIR)/sr_cpost.o $(LIBSARRA_SO_VXX)
	@mkdir -p bin/
	$(CC) $(CFLAGS) $< -o $@ $(LIBSARRA_LINK) $(CLIBS)

bin/sr_cpump: $(APP_ODIR)/sr_cpump.o $(LIBSARRA_SO_VXX)
	@mkdir -p bin/
	$(CC) $(CFLAGS) $< -o $@ $(LIBSARRA_LINK) $(CLIBS)

$(APP_ODIR)/%.o: $(APP_SDIR)/%.c $(HEADERS)
	@mkdir -p $(APP_ODIR)
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@ 

# build libs
lib: $(LIBSARRA_SO_VXX) $(LIBSHIM_SO_VXX)

$(LIBSARRA_SO_VXX): $(LIB_OBJECTS)
	@mkdir -p bin/
	$(CC) $(CFLAGS) -shared -Wl,-soname,$(LIBSARRA_SO_V) $(LIB_OBJECTS) -o $@ -ldl $(CLIBS)
	@ln -frs $(LIBSARRA_SO_VXX) $(LIBSARRA)
	@ln -frs $(LIBSARRA_SO_VXX) $(LIBSARRA_SO_V)

$(LIBSHIM_SO_VXX): $(LIB_ODIR)/libsrshim.o $(LIBSARRA_SO_VXX)
	@mkdir -p bin/
	$(CC) $(CFLAGS) -shared -Wl,-soname,$(LIBSHIM_SO_V) $^ -o $@ -ldl $(CLIBS)

$(LIB_ODIR)/%.o: $(LIB_SDIR)/%.c $(HEADERS)
	@mkdir -p $(LIB_ODIR)
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@ 
	
# build tests
test:

# install application on system
install:

# remove bin/ and obj/
clean:
	@rm -f include/sr_version.h
	@rm -rf bin/ obj/

# set code format
format:
	@indent -linux -l100 *.c *.h
	@rm *.c~ *.h~

# run test suite
check:
