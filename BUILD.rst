
----------------------------------------
Building Sarracenia C Client from Source
----------------------------------------

The metpx-sr3c package is an AMQP C client for creating and consuming Sarracenia messages
implemented in C. It is written in the C programming language and thus requires a normal
C development environment (gcc, make) as well as some C libraries and helpers indicated
below. Valgrind is also used during development to test memory management.

Source Code Documentation
-------------------------

Partial implementation of Doxygen docs.
to view::

  sudo apt install doxygen
  sudo apt install graphviz
  doxygen

and run, and it will create the browseable docs/html/ subdirectory
with some documentation. Although only a few files out of the total
have been properly annoted so far, doxygen is configured to extract
as much information from the code as possible. (We have some pretty
call/caller graphs now!)


Build Dependencies
------------------

The librabbitmq version needs to be > 0.8,  this is newer than what is in
ubuntu 16.04. So you need to git clone from https://github.com/alanxz/rabbitmq-c
then built it there. The launchpad PPA has a backport included to take care of
this::

  export RABBIT_BUILD=*directory where rabbit has been built*


librabbitmq-dev - AMQP client library written in C - Dev Files
libssl-dev  - OpenSSL client library (used for hash algorithms.)
libjson-c-dev - json-c header files.

run dependencies::

  librabbitmq4 - AMQP client library written in C
  libssl - OpenSSL client library.
  libjson-c3 - JSON manupulation library (for v03 parsing)

On RPM-based distributions::
  
  librabbitmq-devel
  json-c-devel

This JSON library changed API multiple times in it's history. Sarrac development
platform is ubuntu 18.04, where the libjson-c3 library is provided.  Older linux
versions may have incompatible library versions and may not build or run correctly.
The Makefile includes the -DHAVE_JSONC option in CFLAGS.  Removing this option
disables v03 message parsing, but makes it possible to build on such systems.
v03 posting will still work (dependency only required to receive messages.)

BUILD 
-----

To build binaries for local testing, there is a Makefile that automates dependencies.
to do a local build, invoke the *make* command::

    [sarra@edcm-dirt-rhel8-1 metpx-sr3c]$ make
    echo "#define __sarra_version__ \"`head -1 debian/changelog| sed 's/.*(//' | sed 's/).*//'`\"" >sr_version.h
    gcc -DINTERCEPT_SYSCALL -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"/lib64/libc.so.6\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE  -c  sr_post.c
    gcc -DINTERCEPT_SYSCALL -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"/lib64/libc.so.6\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE  -c  sr_consume.c
    gcc -DINTERCEPT_SYSCALL -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"/lib64/libc.so.6\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE  -c  sr_context.c
    gcc -DINTERCEPT_SYSCALL -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"/lib64/libc.so.6\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE  -c  sr_config.c
    gcc -DINTERCEPT_SYSCALL -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"/lib64/libc.so.6\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE  -c  sr_event.c
    gcc -DINTERCEPT_SYSCALL -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"/lib64/libc.so.6\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE  -c  sr_credentials.c
    gcc -DINTERCEPT_SYSCALL -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"/lib64/libc.so.6\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE  -c  sr_cache.c
    gcc -DINTERCEPT_SYSCALL -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"/lib64/libc.so.6\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE  -c  sr_util.c
    gcc -DINTERCEPT_SYSCALL -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"/lib64/libc.so.6\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE  -shared -Wl,-soname,libsr3c.so.1 -o libsr3c.so.1.0.0 sr_post.o sr_consume.o sr_context.o sr_config.o sr_event.o sr_credentials.o sr_cache.o sr_util.o -ldl  -ljson-c -lrabbitmq -lcrypto -lc
    gcc -DINTERCEPT_SYSCALL -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"/lib64/libc.so.6\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE  -shared -Wl,-soname,libsr3shim.so.1 -o libsr3shim.so.1.0.0 libsr3shim.c libsr3c.so.1.0.0 -ldl '-Wl,-rpath,$ORIGIN/../lib' -L/home/sarra/metpx-sr3c   -ljson-c -lrabbitmq -lcrypto -lc
    if [ ! -f libsr3c.so ]; \
    then \
            ln -s libsr3c.so.1.0.0 libsr3c.so ; \
    fi;
    if [ ! -f libsr3c.so.1 ]; \
    then \
            ln -s libsr3c.so.1.0.0 libsr3c.so.1 ; \
    fi;
    gcc -DINTERCEPT_SYSCALL -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"/lib64/libc.so.6\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE  -o sr_configtest sr_configtest.c -lsr3c '-Wl,-rpath,$ORIGIN/../lib' -L/home/sarra/metpx-sr3c  -lrabbitmq  -lcrypto
    gcc -DINTERCEPT_SYSCALL -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"/lib64/libc.so.6\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE  -o sr_utiltest sr_utiltest.c -lsr3c '-Wl,-rpath,$ORIGIN/../lib' -L/home/sarra/metpx-sr3c  -lrabbitmq  -lcrypto
    gcc -DINTERCEPT_SYSCALL -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"/lib64/libc.so.6\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE  -o sr_cachetest sr_cachetest.c -lsr3c '-Wl,-rpath,$ORIGIN/../lib' -L/home/sarra/metpx-sr3c  -lrabbitmq  -lcrypto
    gcc -DINTERCEPT_SYSCALL -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"/lib64/libc.so.6\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE  -o sr3_cpost sr3_cpost.c -lsr3c '-Wl,-rpath,$ORIGIN/../lib' -L/home/sarra/metpx-sr3c  -lrabbitmq  -lcrypto
        gcc -DINTERCEPT_SYSCALL -DHAVE_JSONC -DSR_APPNAME=\"sr3\" -DFORCE_LIBC_REGEX=\"/lib64/libc.so.6\" -fPIC -ftest-coverage -std=gnu99 -Wall -g -D_GNU_SOURCE  -o sr3_cpump sr3_cpump.c -lsr3c '-Wl,-rpath,$ORIGIN/../lib' -L/home/sarra/metpx-sr3c  -lrabbitmq  -lcrypto
    [sarra@edcm-dirt-rhel8-1 metpx-sr3c]$

Now the binaries ./sr3_cpost, and ./sr3_cpump, as well as the libsr3c.so and libsr3shim.so libraries are build in the current directory and can be tested.
There are other targets used to run sanity tests.

To modify builds, edit the Makefile, and look for the line that begins with CFLAGS=
In the example above, for example, the -DINTERCEPT_SYSCALL flag has been added (appropriate for redhat 8) CFLAGS to adjust compilation.
Other flags of interest are below:




FORCE_LIBC_REGEX
~~~~~~~~~~~~~~~~

This option is set by default as it is usually desired.
If you see::

  2018-11-21 00:08:17,315 [ERROR] invalid regular expression: .*\/tmp\/.*. Ignored

and the regex is valid... the symptom we had was that the library was
calling a version of the regular expresison routines included in a binary
(ksh93 in this case) instead of the ones in libc that were expected.
without this option being set, the shim library will compile and user
Korn Shell regular expression grammar instead of the libc/posix ones.
This is confusing in practice.

Set the option::
   
   -DFORCE_LIBC_REGEX=\"/lib/x86_64-linux-gnu/libc.so.6\" 

to the file containing the regcomp and regexec routines what are to be 
used. The code uses dynamic library loading to force use of the specified
routines. Obviously this setting is architecture dependent and would
need adjustment if compiling on another platform, such as ARM or MIPS.
 
SR_DEBUG_LOGS
~~~~~~~~~~~~~

To disable all log file support, so that diagnostics messages 
are sent to standard error instead, include::

  -DSR_DEBUG_LOGS=1




Testing
--------

trust_but_verify
~~~~~~~~~~~~~~~~

ensure the c is compiled correctly, and the caching logic works::

    make trust_but_verify

It tests caching logic, and the timing is a little finicky, and timing
out of the last entry can sometimes cause failures.  If that is all that is wrong,
just run the test again.

It may not pass the first time through.  Just try again. Once it has run through the
cache checks, it will run valgrind, and there should be no memory allocation problems.


shim_post
~~~~~~~~~

To run the next tests that validate the shim library, one must have a broker available
to post to and set BROKER appropriately. defaults are like below::

    export BROKER=amqp://tfeed@localhost

(assumes a local broker is configured and working using the python tools.)
Then can run the test::

     make test_shim_post

All tests should, ideally, succeed.  on redhat8, they don't so we cannot proceed to the next
tests. On redhat8, there is a bug related to re-direction not working.  so you need to
set KNOWN_REDIRECTION_BUG=y, and run the tests again::

    [sarra@edcm-dirt-rhel8-1 metpx-sr3c]$ export KNOWN_REDIRECTION_BUG=y
    [sarra@edcm-dirt-rhel8-1 metpx-sr3c]$ make test_shim_post
    ./shim_post.sh >shim_post.log 2>&1
    #python3 ./check_shim_post.py shim_post.log exit_on_bad
    python3 ./check_shim_test.py shim_post.log
    RESULT: comment 000 shim test posting start
    2024-07-24 12:22:00,612 [INFO] shim published: { "pubTime":"20240724162200.6124081", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/hoho", "topic":"v03.post.metpx-sr3c", "identity":{  "method" : "sha512", "value" : "V/BeoaZp+hh0CbopUiR/1kckdUspp4oAnsDmhZhaIXVKb3gGPB5lrT62enDtl5lxQ/e+vO9GsuoRH1\nY+rlGhxQ=="  } , "mtime":"20240724162200.60770176", "atime":"20240724162200.60670166", "mode":"0664", "size":"5", "toto":"pig"}
    
    RESULT: Good! 1 sha512 posts from 010 capturing stdout. as expected
    2024-07-24 12:22:00,619 [INFO] shim published: { "pubTime":"20240724162200.61952043", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/hoho", "topic":"v03.post.metpx-sr3c", "identity":{  "method" : "sha512", "value" : "oLy3C3cd4fYUxySoYWkojuncdJpsC7ud0PhjwrZlMdIbZbgb09PsTjRcL+pZAyobTz/lIxfaO/B1N0\n97aZsQqg=="  } , "mtime":"20240724162200.61370234", "atime":"20240724162200.61070205", "mode":"0664", "size":"2", "toto":"pig"}
    
    RESULT: Good! 1 sha512 posts from 020 c program run.. as expected
    2024-07-24 12:22:00,637 [INFO] shim published: { "pubTime":"20240724162200.63695751", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/hoho", "topic":"v03.post.metpx-sr3c", "identity":{  "method" : "sha512", "value" : "m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G\n9zvN7AQw=="  } , "mtime":"20240724162200.63270418", "atime":"20240724162200.61870282", "mode":"0664", "size":"5", "toto":"pig"}
    
    RESULT: Good! 1 sha512 posts from 030 python program run. as expected
    2024-07-24 12:22:00,647 [INFO] shim published: { "pubTime":"20240724162200.64737922", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/sub_dir1", "topic":"v03.post.metpx-sr3c", "mtime":"20240724162200.64270515", "atime":"20240724162200.64270515", "mode":"0775", "toto":"pig", "fileOp" : { "directory":""}}
    
    RESULT: Good! 1 directory posts from 040 make directory. as expected
    2024-07-24 12:22:00,653 [INFO] shim published: { "pubTime":"20240724162200.65374716", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/sub_dir2", "topic":"v03.post.metpx-sr3c", "mtime":"20240724162200.64270515", "atime":"20240724162200.64270515", "mode":"0775", "toto":"pig", "fileOp" : { "directory":"", "rename" : "sub_dir1" }}
    
    RESULT: Good! 1 rename posts from 050 rename directory. as expected
    2024-07-24 12:22:00,659 [INFO] shim published: { "pubTime":"20240724162200.65962601", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/sub_dir2", "topic":"v03.post.metpx-sr3c", "toto":"pig", "fileOp" : { "rmdir":""}}
    
    RESULT: Good! 1 rmdir posts from 060 remove directory. as expected
    2024-07-24 12:22:00,666 [INFO] shim published: { "pubTime":"20240724162200.66582152", "baseUrl":"file:/home/sarra", "relPath":"test/hoho_my_darling.txt", "topic":"v03.post.test", "identity":{  "method" : "sha512", "value" : "ZjDeqDLkEcT7j8fhfpiJIb6ledKyXWI0Ve5bctx6N4nRo+x5tNZFAPsAX/eJGefkvHUnw5Gh3fKNFF\ns7Yn254g=="  } , "mtime":"20240724162200.6607069", "atime":"20240724162200.6607069", "mode":"0664", "size":"42273", "toto":"pig"}
    
    RESULT: Good! 1 sha512 posts from 070 cp command. as expected
    2024-07-24 12:22:00,672 [INFO] shim published: { "pubTime":"20240724162200.67182824", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/hihi", "topic":"v03.post.metpx-sr3c", "identity":{  "method" : "sha512", "value" : "z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlOD\nJ6+SfaPg=="  } , "mtime":"20240724162200.66870767", "atime":"20240724162200.66870767", "mode":"0664", "size":"0", "toto":"pig"}
    
    RESULT: Good! 1 sha512 posts from 080 touch command. as expected
    2024-07-24 12:22:00,677 [INFO] shim published: { "pubTime":"20240724162200.67748101", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/haha", "topic":"v03.post.metpx-sr3c", "toto":"pig", "fileOp" : { "link":"hoho"}}
    
    RESULT: Good! 1 link posts from 090 symlink command. as expected
    2024-07-24 12:22:00,684 [INFO] shim published: { "pubTime":"20240724162200.68408558", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/hihi", "topic":"v03.post.metpx-sr3c", "toto":"pig", "fileOp" : { "link":"hoho", "rename" : "haha" }}
    
    RESULT: Good! 1 rename posts from 100 moving a symlink. as expected
    2024-07-24 12:22:00,690 [INFO] shim published: { "pubTime":"20240724162200.69031104", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/hoohoo", "topic":"v03.post.metpx-sr3c", "toto":"pig", "fileOp" : { "link":"hoho", "rename" : "hihi" }}
    
    RESULT: Good! 1 rename posts from 110 hardlink to a symlink. as expected
    2024-07-24 12:22:00,696 [INFO] shim published: { "pubTime":"20240724162200.69622963", "baseUrl":"file:/home/sarra", "relPath":"test/hoho2.log", "topic":"v03.post.test", "identity":{  "method" : "sha512", "value" : "ZjDeqDLkEcT7j8fhfpiJIb6ledKyXWI0Ve5bctx6N4nRo+x5tNZFAPsAX/eJGefkvHUnw5Gh3fKNFF\ns7Yn254g=="  } , "mtime":"20240724162200.6607069", "atime":"20240724162200.66470728", "mode":"0664", "size":"42273", "toto":"pig", "fileOp": { "rename" : "/home/sarra/test/hoho_my_darling.txt" }}
    
    RESULT: Good! 1 rename posts from 120 moving a file.. as expected
    2024-07-24 12:22:00,702 [INFO] shim published: { "pubTime":"20240724162200.70214724", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/hihi", "topic":"v03.post.metpx-sr3c", "toto":"pig", "fileOp" : { "remove":""}}
    
    RESULT: Good! 1 remove posts from 130 removing a file.. as expected
    2024-07-24 12:22:00,708 [INFO] shim published: { "pubTime":"20240724162200.70795871", "baseUrl":"file:/home/sarra", "relPath":"test/hoho2.log", "topic":"v03.post.test", "toto":"pig", "fileOp" : { "remove":""}}
    
    RESULT: Good! 1 remove posts from 140 removing a file.. as expected
    2024-07-24 12:22:00,714 [INFO] shim published: { "pubTime":"20240724162200.71400629", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/dirone", "topic":"v03.post.metpx-sr3c", "mtime":"20240724162200.70971165", "atime":"20240724162200.70971165", "mode":"0775", "toto":"pig", "fileOp" : { "directory":""}}
    
    RESULT: Good! 1 directory posts from 150 make second directory .. as expected
    2024-07-24 12:22:00,720 [INFO] shim published: { "pubTime":"20240724162200.7206274", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/dirone/fileone", "topic":"v03.post.metpx-sr3c.dirone", "identity":{  "method" : "sha512", "value" : "m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G\n9zvN7AQw=="  } , "mtime":"20240724162200.71571223", "atime":"20240724162200.71571223", "mode":"0664", "size":"5", "toto":"pig"}
    
    RESULT: Good! 1 sha512 posts from 160 cp to avoid stdout redirection in a subdir. as expected
    2024-07-24 12:22:00,726 [INFO] shim published: { "pubTime":"20240724162200.72676479", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/dirone/dirtwo", "topic":"v03.post.metpx-sr3c.dirone", "mtime":"20240724162200.72171281", "atime":"20240724162200.72171281", "mode":"0775", "toto":"pig", "fileOp" : { "directory":""}}
    
    RESULT: Good! 1 directory posts from 170 make third directory.. as expected
    2024-07-24 12:22:00,733 [INFO] shim published: { "pubTime":"20240724162200.73313262", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/dirone/dirtwo/filetwo", "topic":"v03.post.metpx-sr3c.dirone.dirtwo", "identity":{  "method" : "sha512", "value" : "m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G\n9zvN7AQw=="  } , "mtime":"20240724162200.72871349", "atime":"20240724162200.72871349", "mode":"0664", "size":"5", "toto":"pig"}
    
    RESULT: Good! 1 sha512 posts from 180 cp to avoid stdout redirection in a subsubdir. as expected
    2024-07-24 12:22:00,739 [INFO] shim published: { "pubTime":"20240724162200.73938894", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/dirthree", "topic":"v03.post.metpx-sr3c", "mtime":"20240724162200.72171281", "atime":"20240724162200.70971165", "mode":"0775", "toto":"pig", "fileOp" : { "directory":"", "rename" : "dirone" }}
    
    RESULT: Good! 1 rename posts from 190 renaming subdirs should cause file rename events.. as expected
    2024-07-24 12:22:00,745 [INFO] shim published: { "pubTime":"20240724162200.74513463", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/dirthree/fileone", "topic":"v03.post.metpx-sr3c.dirthree", "toto":"pig", "fileOp" : { "remove":""}}
    
    2024-07-24 12:22:00,745 [INFO] shim published: { "pubTime":"20240724162200.74544573", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/dirthree/dirtwo/filetwo", "topic":"v03.post.metpx-sr3c.dirthree.dirtwo", "toto":"pig", "fileOp" : { "remove":""}}
    
    2024-07-24 12:22:00,745 [INFO] shim published: { "pubTime":"20240724162200.74571733", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/dirthree/dirtwo", "topic":"v03.post.metpx-sr3c.dirthree", "toto":"pig", "fileOp" : { "remove":""}}
    
    2024-07-24 12:22:00,746 [INFO] shim published: { "pubTime":"20240724162200.74589953", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/dirthree", "topic":"v03.post.metpx-sr3c", "toto":"pig", "fileOp" : { "remove":""}}
    
    RESULT: Good! 4 remove posts from 200 removing a whole tree events.. as expected
    2024-07-24 12:22:00,751 [INFO] shim published: { "pubTime":"20240724162200.7514974", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/hoho", "topic":"v03.post.metpx-sr3c", "toto":"pig", "fileOp" : { "remove":""}}
    
    2024-07-24 12:22:00,751 [INFO] shim published: { "pubTime":"20240724162200.75180644", "baseUrl":"file:/home/sarra", "relPath":"metpx-sr3c/hoohoo", "topic":"v03.post.metpx-sr3c", "toto":"pig", "fileOp" : { "remove":""}}
    
    RESULT: Good! 2 remove posts from 210 removing two files. as expected
    RESULT: comment 220 shim test posting end
    posts: {'sha512': 7, 'directory': 3, 'rename': 5, 'rmdir': 1, 'link': 1, 'remove': 8}
    RESULT: summary: good: 21, bad 0, total 21
    [sarra@edcm-dirt-rhel8-1 metpx-sr3c]$


IF that passes, then the next tests are::

     make test_shim

which will run test_shim_post again, and then mirror sub-directories of the local directory using many 
different combinations of options. Project for future... get things to work on redhat without
the KNOW_REDIRECTION_BUG being set.


Build a Debian Package
----------------------

if on a debian derived OS, then assuming build dependencies are taken
care of::

  debuild -uc -us

will build a package you can install:

* using the source code in the current directory. 
* placing the .dpkg files in the parent directory.
* The current directory might need to be named metpx-sr3c (might only be a requirement for rpm builds... not sure.)


Build an RPM Package
--------------------

if on a redhat derived OS, then assuming build dependencies are taken 
care of. For redhat 8, add the INTERCEPT_SYSCALL symbol to CFLAGS in the
Makefile::

   vi Makefile
   /^CFLAGS=
   a -DINTERCEPT_SYSCALL <Esc>
   :wq


For all Redhat versions::

   make rpm_rhel7


Will run rpmbuild, and put the packages where that tool places them
(under ~/rpmbuild/RPMS )


There is also a suse Makefile target. Has not be tested recently.
May or may not work. Left as a starting point for next person to try Suse.


Branches
--------

The main repository of sarrac is: https://github.com/MetPX/sarrac
As of 2022/12, development is on v3 compatible version of sarrac, now called metpx-sr3c.
The customer switched to sr3, so there is no need to continue with v2.
The existing git branches and their roles:

* development ... the default development branch, launchpad.net daily packages built from here.
* pre-release ... v03 pre-release branch, tracks development punctually. launchpad.net pre-release packages built from here.
* stable ... v03 release branch, tracks pre-release punctually. launchpad.net stable packages built from here.
* v2 ... v2 development branch. (legacy)
* v2_stable ... v2 release branch, tracks v2 punctually. (legacy)
* issueXXX ... branch developed to address a particular issue.


Release Process
---------------

See `Releases <Release.rst>`_

Proposed Coding Style Guidelines
--------------------------------

Generally, we used `Linux Kernel C Guidelines <https://www.kernel.org/doc/html/v4.10/process/coding-style.html>`_

but with one pythonic affectation:  You know Rule 1? about the tabs with 8 characters?  This code base is normally
indented like python instead, use four spaces, and not tabs.

Also, in terms of documenting code, when adding new things one should add comments
keeping in mind compatbility with `doxygen <http://www.doxygen.nl/manual/docblocks.html>`_ 
Examples::

  /**
   *  descriptive comment above a struct or function declaration.
   */ 

  /**
   * sr_config_find_one() - find the name configuration file name 
   * \param sr_cfg:       The configuration to be updated with the configuration found.
   * \param original_one: The name provided by the user.
   *
   * Return pointer to the matching mask if there is one, NULL otherwise.
   * The pointer to char will hold the absolute path of the config file corresponding to original_one
   *
   * Return: pointer to a static char buffer with a path name to the corresponding configuration file.
   */

  char foo; /**< description of foo class member */


The code has a mix of comments is not entirely doxygen friendly just yet.  Feel free
to improve.  Other than that... the kernel C guidelines are the rule.

FIXME: We ran a code reformatter on it once... should probably repeat from time to time, would be 
useful to document which one was used. I believe it undoes for the pythonic exception.
