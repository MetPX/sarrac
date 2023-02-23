# 
# if rabbitmq library is provided by SSM package, RABBITMQC_HOME is required. 
# 
ifdef RABBITMQC_HOME
RABBIT_LIBDIR = ${RABBITMQC_HOME}/lib
RABBIT_INCDIR = -I${RABBITMQC_HOME}/include
RABBIT_LINK = -Wl,-rpath,${RABBIT_LIBDIR} -L${RABBIT_LIBDIR}
endif

# If rabbitmq library is only built (not installed) then set RABBIT_BUILD
ifdef RABBIT_BUILD
RABBIT_LIBDIR=${RABBIT_BUILD}/build/librabbitmq
RABBIT_INCDIR = -I${RABBIT_BUILD}/librabbitmq
RABBIT_LINK = -Wl,-rpath,${RABBIT_LIBDIR} -L${RABBIT_LIBDIR}
endif

SARRA_LIBDIR = ${CURDIR}

SARRA_LINK = '-Wl,-rpath,$$ORIGIN/../lib' -L${SARRA_LIBDIR} 

# if neither variable is set, then it is assumed to be available from default environment.

CC = gcc

# can also use intel compiller just by changing CC
# CC = icc

# add -DSR_DEBUG_LOGS to CFLAGS to replace log files with writing to stderr, and much improved compiler checks.
#    if you try the explain library, need to add -lexplain to SARRA_LINK also.

LIBCLOCATION=$(shell ldd /bin/sh | awk '/libc\.so\./ { print; }' | cut -d' ' -f3 )

# if your system doesn't have a good version of libjson-c, then 
# remove -DHAVE_JSONC from CFLAGS to remove dependency on libjson-c for OS's where libjson-c is not available easily.
#     when you do this, you can no longer accept v03 messages, but you can still post them.
#
# also remove -ljson-c from EXT_LIB declaration.
# to work with sr3, change SR_APPNAME=\"sr3\" ... otherwise will be managed by version 2. 
# on Power9, -fstack-check  causes coredumps, so removed for now.

CFLAGS = -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"$(LIBCLOCATION)\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE $(RABBIT_INCDIR)

SARRA_HEADER = sr_cache.h sr_config.h sr_consume.h sr_context.h sr_credentials.h sr_event.h sr_post.h sr_util.h sr_version.h uthash.h 
SARRA_OBJECT = sr_post.o sr_consume.o sr_context.o sr_config.o sr_event.o sr_credentials.o sr_cache.o sr_util.o
SARRA_LIB = libsr3c.so.1.0.0 
EXT_LIB = -ljson-c -lrabbitmq -lcrypto -lc
SHARED_LIB = libsr3shim.so.1 -o libsr3shim.so.1.0.0 libsr3shim.c libsr3c.so.1.0.0

.c.o: $(SARRA_HEADER) Makefile
	$(CC) $(CFLAGS) -c  $<

#  head -1 debian/changelog | sed 's/.*(//' | sed 's/).*//'
all: sr_version.h $(SARRA_OBJECT)
	$(CC) $(CFLAGS) -shared -Wl,-soname,libsr3c.so.1 -o libsr3c.so.1.0.0 $(SARRA_OBJECT) -ldl $(RABBIT_LINK) $(EXT_LIB)
	$(CC) $(CFLAGS) -shared -Wl,-soname,$(SHARED_LIB) -ldl $(SARRA_LINK) $(RABBIT_LINK) $(EXT_LIB)
	if [ ! -f libsr3c.so ]; \
	then \
		ln -s libsr3c.so.1.0.0 libsr3c.so ; \
	fi;
	if [ ! -f libsr3c.so.1 ]; \
	then \
		ln -s libsr3c.so.1.0.0 libsr3c.so.1 ; \
	fi;
	$(CC) $(CFLAGS) -o sr_configtest sr_configtest.c -lsr3c $(SARRA_LINK) -lrabbitmq $(RABBIT_LINK) -lcrypto
	$(CC) $(CFLAGS) -o sr_utiltest sr_utiltest.c -lsr3c $(SARRA_LINK) -lrabbitmq $(RABBIT_LINK) -lcrypto
	$(CC) $(CFLAGS) -o sr_cachetest sr_cachetest.c -lsr3c $(SARRA_LINK) -lrabbitmq $(RABBIT_LINK) -lcrypto
	$(CC) $(CFLAGS) -o sr3_cpost sr3_cpost.c -lsr3c $(SARRA_LINK) -lrabbitmq $(RABBIT_LINK) -lcrypto
	$(CC) $(CFLAGS) -o sr3_cpump sr3_cpump.c -lsr3c $(SARRA_LINK) -lrabbitmq $(RABBIT_LINK) -lcrypto

#debian/changelog: ../sarracenia/debian/changelog
#	sed 's/^metpx-sarracenia/libsarra-c/' <../sarracenia/debian/changelog >debian/changelog 

sr_version.h: debian/changelog
	echo "#define __sarra_version__ \"`head -1 debian/changelog| sed 's/.*(//' | sed 's/).*//'`\"" >sr_version.h

install:
	@mkdir -p build build/bin build/lib build/include
	@mv *.so build/lib
	@mv *.so.1 build/lib
	@mv *.so.*1.0.0 build/lib
	@mv sr3_cpost build/bin
	@mv sr3_cpump build/bin
	@cp *.h build/include/
	@if [ $$(echo "$(DESTDIR)" | grep "rpmbuild") ]; \
	then \
		mkdir -p $(DESTDIR)/usr; \
		cp -r build/lib $(DESTDIR)/usr/lib64; \
		cp -r build/bin $(DESTDIR)/usr/bin; \
		cp -r build/include $(DESTDIR)/usr/include; \
	fi;

rpm_suse15:
	rpmbuild --build-in-place -bb metpx-sr3c_suse15.spec 

metpx-sr3c_rhel7.spec: sr_version.h metpx-sr3c_rhel7.spec.tem
	 sed 's/__sarra_version__/'`head -1 debian/changelog| sed 's/.*(//' | sed 's/).*//'`'/' <metpx-sr3c_rhel7.spec.tem >metpx-sr3c_rhel7.spec

rpm_rhel7: metpx-sr3c_rhel7.spec
	rpmdev-setuptree
	echo "%_unpackaged_files_terminate_build      0" > ~/.rpmmacros
	echo "%_binaries_in_noarch_packages_terminate_build   0" >> ~/.rpmmacros
	tar -czvf /tmp/metpx-sr3c.tar.gz ../metpx-sr3c
	cp -p /tmp/metpx-sr3c.tar.gz `rpm --eval "%{_sourcedir}"`
	rpmbuild -bb metpx-sr3c_rhel7.spec

format:
	indent -linux -l100 *.c *.h
	rm *.c~ *.h~

clean:
	rm -f *.o *.gcno *.so *.so.* sr3_cpost sr_configtest sr_utiltest sr3_cpump sr_cachetest sr_cache_save.test shim_test.log
	rm -rf build sr_version.h metpx-sr3c_rhel7.spec

trust_but_verify: all
	export LD_LIBRARY_PATH=`pwd`:${LD_LIBRARY_PATH}; ./sr_configtest test_post.conf 
	export LD_LIBRARY_PATH=`pwd`:${LD_LIBRARY_PATH}; ./sr_utiltest 
	export LD_LIBRARY_PATH=`pwd`:${LD_LIBRARY_PATH}; ./sr_cachetest
	export LD_LIBRARY_PATH=`pwd`:${LD_LIBRARY_PATH}; valgrind --show-reachable=yes --track-origins=yes ./sr3_cpost -c local_post.conf uthash.h

test_shim_post: 
	-./shim_post.sh >shim_post.log 2>&1
	#python3 ./check_shim_post.py shim_post.log exit_on_bad
	python3 ./check_shim_test.py shim_post.log

test_shim_copy:
	-./shim_copy.sh >shim_copy.log 2>&1
	#python3 ./check_shim_test.py shim_copy.log exit_on_bad
	python3 ./check_shim_test.py shim_copy.log 

test_shim: test_shim_post test_shim_copy
