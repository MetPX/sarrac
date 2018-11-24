
---------------------------------------
C-Implementation of a Sarracenia Client
---------------------------------------

This C functionality is not intended to be a complete
implementation, it is just a few pieces meant to provide interoperability for
cases where either a python3 environment is either impractical, or where there
are performance concerns that this implementation would help with..

 - in some environments getting python3 environment installed is hard
   (example: cray linux environment is a software environment from circa 2009)

 - in-process invocation of sr_post on file closes (libsrshim.)

Installation
------------

easiest way to obtain it, if you are on Ubuntu 14.04/16.04/17.10/18.04) is to
use the PPA on Launchpad.net::

  sudo add-apt-repository ppa:ssc-hpc-chp-spc/metpx
  sudo apt-get update
  sudo apt-get install sarrac

if on another debian derived OS, then assuming build dependencies are taken 
care of::

  debuild -uc -us

will build a package you can install.  Otherwise just *make*, and you need
to install the bits yourself.


Use
---


A library, libsarra is built, with external interfaces one can access from C 
using the entry points and data structures documented in sr_context.h, 
sr_post.h, and sr_consume.h files. The library uses sr_subscribe(1) style config
files (see Limitations). A sample usage of the libraries is a command line
binary, that can call the library::

   sr_cpost

This function takes the same options as sr_post, but the *sleep* argument, 
when supplied causes it to loop, checking for new items every *sleep* seconds 
(equivalent to sr_watch.) There is also a sample consumer::

  sr_cpump

which obtains messages and, by default, prints them to standard output in json
format identical the the format used by the python implementation for 
save/restore. In order to have a complete downloader, one needs a script to
parse the json output and invoke an appropriate binary downloader.  One can
use the 'outlet' switch to choose other formats:
 
json:
  the default format, json compatible with python save/restore.

post:
  turns sr_cpump into an sr_shovel, if cache is on, then it is a winnow.

url: 
  just print out the retrieval urls, rather than the entire message

There is also an LD_PRELOAD shim library. (libsrshim.c) that uses the posting
API, this is to be used in `very high volume use cases <https://github.com/MetPX/sarracenia/blob/master/doc/mirroring_use_case.rst>`_
 ) sample usage::

   export SR_POST_CONFIG="mypost"
   export LD_PRELOAD=`pwd`/libsrshim.so.1.0.0
   #export SR_POST_READS=true
   #export SR_SHIMDEBUG=true 

   cp libsrshim.c ~/test/hoho_my_darling.txt
   ln -s hoho haha
   rm haha

With the SR_POST_CONFIG set to "mypost", The libsrshim library will look in 
~/.config/sarra/post/  for "mypost.conf." With the LD_PRELOAD set to use the
library, processes that run will call functions like 'close' that are in the
shim library, and the shim library will apply the "mypost.conf" configuration
to figure out whether it should post the file being closed, and if so, to what
broker.  

Normally, posting  will only occur for files that have been written. If one
wants to post files opened even in readonly mode, this triggers more overhead
as even trivial programs such as *cat* need to configure a connection to the
broker in case they end up posting to it. Normally, the connection is only
established when there is a modified file is checked for posting. To enable
full access monitoring, set the SR_POST_READS variable. This provides an
auditing function and/or the ability to mirror a complete environment (even
files that we didn't know we needed.)

If the SR_SHIMDEBUG variable is set, rather verbose messaging will occur.


Limitations of the C implementation
-----------------------------------

 - This library and tools do not work with any plugins from the python 
   implementation.

 - This library is a single process oriented, the *instances* setting 
   is ignored.

 - The queue settings established by a consumer are not the same as those
   of the python implementation, so queues cannot be shared between the two.

 - The shim library is very Linux specific. Porting to other operating systems
   will be a significant re-write.

 - The C is infected by python taste... 4 character indent, with spaces, all
   the time.


Build Dependencies
------------------

The librabbitmq version needs to be > 0.8,  this is newer than what is in
ubuntu 16.04. So you need to git clone from https://github.com/alanxz/rabbitmq-c
then built it there. The launchpad PPA has a backport included to take care of
this::

  export RABBIT_BUILD=*directory where rabbit has been built*


librabbitmq-dev - AMQP client library written in C - Dev Files
libssl-dev  - OpenSSL client library (used for hash algorithms.)

run dependencies::

  librabbitmq4 - AMQP client library written in C
  libssl - OpenSSL client library.


BUILD OPTIONS
-------------

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
This could be confusing in practic.

Set the option -DFORCE_LIBC_REGEX=\"/lib/x86_64-linux-gnu/libc.so.6\" to
the file containing the regcomp and regexec routines what are to be 
used. The code uses dynamic library loading to force use of the specified
routines. Obviously this setting is architecture dependent and would
need adjustment if compiling on another platform, such as ARM or MIPS.
 
SR_DEBUG_LOGS
~~~~~~~~~~~~~

To disable all log file support, so that diagnostics messages 
are sent to standard error instead, include -DSR_DEBUG_LOGS=1


Dorval Computing Centre
-----------------------

If you are in the Dorval computing centre environment, then 
`SSM <https://expl.info/display/SSM>`_ is available and a compatible version
of rabbitmq-c can be obtained ::

  . ssmuse-sh -d /fs/ssm/main/opt/rabbitmqc/rabbitmqc-0.8.0
 
To load sr_cpost::

  . ssmuse-sh -d /fs/ssm/hpco/exp/sarrac-2.18.05b4
 

Release Process
---------------

To note changes:
  - dch, and add your points.
  - when ready to release, edit UNRELEASED to an appropriate status, usually unstable.
  - git commit #what you need to commit...
  - git tag <release> -m <release>
  - git push
  - git push tag <release>

  - go to Launchpad, and import source `here <https://code.launchpad.net/~ssc-hpc-chp-spc/metpx-sarrac/+git/master>`_.
  - go to launchpad, find the recipe and Request Build `here <https://code.launchpad.net/~ssc-hpc-chp-spc/+recipe/metpx-sarrac>`_.

