.PHONY: all app lib test install clean format check

### COMPILATION FLAGS ###
CC		= gcc
CLIBS		= -lrabbitmq -lcrypto
CFLAGS		= -fPIC -ftest-coverage -fstack-check -std=gnu99 -Wall -g -D_GNU_SOURCE
INCLUDES	= -Iinclude/

### FILES & PARAMETERS ##
SO_V		:= 1
SO_VXX		:= 1.0.0
HEADERS		:= $(wildcard include/*.h)

APP_SDIR	:= src/app
LIB_SDIR	:= src/lib
APP_SOURCES	:= $(wildcard src/app/*.c)
LIB_SOURCES	:= $(wildcard src/lib/*.c)

APP_ODIR	:= obj/app
LIB_ODIR	:= obj/lib
APP_OBJECTS	:= $(APP_SOURCES:src/app/%.c=obj/app/%.o)
LIB_OBJECTS	:= $(LIB_SOURCES:src/lib/%.c=obj/lib/%.o) 

# build all components
all: lib app
	@rm -rf obj/

# build apps
app: lib bin/sr_cpost bin/sr_cpump

bin/sr_cpost: $(HEADERS) bin/libsarra.so $(APP_ODIR)/sr_cpost.o
	@mkdir -p bin/
	$(CC) $(CFLAGS) $(APP_ODIR)/sr_cpost.o bin/libsarra.so -o $@ $(CLIBS)

bin/sr_cpump: $(HEADERS) bin/libsarra.so $(APP_ODIR)/sr_cpump.o
	@mkdir -p bin/
	$(CC) $(CFLAGS) $(APP_ODIR)/sr_cpump.o bin/libsarra.so -o $@ $(CLIBS)

$(APP_ODIR)/%.o: $(APP_SDIR)/%.c
	@mkdir -p $(APP_ODIR)
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@ 

# build libs
lib: bin/libsarra.so bin/libsrshim.so
	@mv bin/libsrshim.so bin/libsrshim.so.$(SO_VXX)
	@mv bin/libsarra.so bin/libsarra.so.$(SO_VXX)
	@ln -rs bin/libsarra.so.$(SO_VXX) bin/libsarra.so
	@ln -rs bin/libsarra.so.$(SO_VXX) bin/libsarra.so.$(SO_V)

bin/libsarra.so: $(HEADERS) $(LIB_OBJECTS)
	@mkdir -p bin/
	$(CC) $(CFLAGS) -shared $(LIB_OBJECTS) -o $@ $(CLIBS)

bin/libsrshim.so: $(HEADERS) bin/libsarra.so $(LIB_ODIR)/libsrshim.o
	@mkdir -p bin/
	$(CC) $(CFLAGS) -shared $(LIB_ODIR)/libsrshim.o bin/libsarra.so -o $@ $(CLIBS)

$(LIB_ODIR)/%.o: $(LIB_SDIR)/%.c
	@mkdir -p $(LIB_ODIR)
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
