
---------------------------------------
C-Implementation of a Sarracenia Client
---------------------------------------

This C functionality is not a complete implementation, only a few pieces meant 
to provide interoperability for cases where either a python3 environment is 
either impractical, or where there are performance concerns that this 
implementation would help with:

 - in some environments getting python3 environment installed is hard
   (example: cray linux environment is a software environment from circa 2009)

 - in-process invocation of sr3_post on file closes (libsr3shim.)

Detailed use case:

  https://metpx.github.io/sarracenia/Explanation/History/HPC_Mirroring_Use_Case.html

.. Contents::


Installation
------------

easiest way to obtain it, if you are on Ubuntu >= 18.04, is to
use the PPA on Launchpad.net::

  sudo add-apt-repository ppa:ssc-hpc-chp-spc/metpx
  sudo apt-get update
  sudo apt-get install metpx-sr3c

if on another debian derived OS, then assuming build dependencies are taken 
care of::

  debuild -uc -us

will build a package you can install.  Otherwise just *make*, and you need
to install the bits yourself.


Use
---

A library, libsarra is built, with external interfaces one can access from C 
using the entry points and data structures documented in sr_context.h, 
sr_post.h, and sr_consume.h files. The library uses `sr3 options(7) <https://metpx.github.io/sarracenia/Reference/sr3_options.7.html>`_
style config files (see Limitations). A sample usage of the libraries is a command line
binary, that can call the library::

   sr3_cpost

This function takes the same options as 
`sr3_post <https://metpx.github.io/sarracenia/Reference/sr3_post.1.html>`_.

but the *sleep* argument, when supplied causes it to loop, checking for new 
items every *sleep* seconds (equivalent to sr3_watch.) There is also a sample consumer::

  sr3_cpump

which obtains messages and, by default, prints them to standard output in json
format identical the the format used by the python implementation for 
save/restore. 

`sr3_cpump <https://metpx.github.io/sarracenia/Reference/sr3_cpump.1.html>`_.

In order to have a complete downloader, one needs a script to
parse the json output and invoke an appropriate binary downloader. One can
use the 'outlet' switch to choose other formats:
 
json:
  the default format, json compatible with python save/restore.

post:
  turns sr3_cpump into an sr3 shovel, if cache is on, then it is a winnow.

url: 
  just print out the retrieval urls, rather than the entire message

There is also an LD_PRELOAD shim library. (libsr3shim.c) that uses the posting
API, this is to be used in `very high volume use cases <https://github.com/MetPX/sarracenia/blob/main/doc/hpc_mirroring_use_case.rst>`_

Sample usage::

   export SR_POST_CONFIG="mypost"
   export LD_PRELOAD=`pwd`/libsr3shim.so.1.0.0
   #export SR_POST_READS=true
   #export SR_SHIMDEBUG=true 

   cp libsr3shim.c ~/test/hoho_my_darling.txt
   ln -s hoho haha
   rm haha

With the SR_POST_CONFIG set to "mypost", The libsr3shim library will look in 
~/.config/sarra/post/  for "mypost.conf." With the LD_PRELOAD set to use the
library, processes that run will call functions like 'close' that are in the
shim library, and the shim library will apply the "mypost.conf" configuration
to figure out whether it should post the file being closed, and if so, to what
broker.  

Normally, posting  will only occur for files that have been written.  If one 
wants to post files opened even in readonly mode, this triggers more overhead
as even trivial programs such as *cat* need to configure a connection to the
broker in case they end up posting to it. Normally, the connection is only
established when there is a modified file is checked for posting. To enable
full access monitoring, set the SR_POST_READS variable. This provides an
auditing function and/or the ability to mirror a complete environment (even
files that we didn't know we needed.)

Experimental settings in the shim library. These are configurable for now,
perhaps we will see what the best values are and eliminate the options::

   shim_defer_posting_to_exit 

When shim_defer_posting_to_exit is set (default: False), instead of posting 
files during process execution, (potentially posting the same file 
multiple times.) the shim library will accumulate file names, and only 
post when the process exits. An opposite approach::

   shim_post_minterval

The *shim_post_minterval* setting (default: 5 seconds) establishes the minimum
time interval between repeated posts of the same file.  when a file
is being rapidly re-written multiple times, it is unproductive to post
an advertisement about a file whose state will be different by the time
a client can download it. defines the maximum frequency a single
file will be posted::

   shim_post_once 

When set, The shim_post_once (default: False) does duplicate suppression 
based only on the file name within a single process. the shim library 
cannot use the duplicate suppression cache used by other calls, because 
the cache is not multi-thread safe (expects to be run by a single task.) 
A per process cache might *do the right thing*.::

   shim_skip_parent_open_files

The shim_skip_parent_open_files (default: True) option means that a 
process checks whether the parent process has the same file open, and 
does not post if that is the case, sinc the parent will take care
of it eventually.


 
If the SR_SHIMDEBUG variable is set, rather verbose messaging will occur.

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

Limitations of the C implementation
-----------------------------------

 - This library and tools do not work with any plugins from the python 
   implementation.

 - This library is a single process oriented, the *instances* setting 
   is ignored.

 - The shim library is very Linux specific. Porting to other operating systems
   will be a significant re-write.

 - The C implementation uses the libc(7) regular expression routines, which 
   are a little more limited than python ones.

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


Dorval Computing Centre
-----------------------

If you are in some Dorval computing centre environments, then 
`SSM <https://expl.info/display/SSM>`_ is available and a compatible version
of rabbitmq-c can be obtained ::

  . ssmuse-sh -d /fs/ssm/main/opt/rabbitmqc/rabbitmqc-0.8.0
 
To load sr3_cpost::

  . ssmuse-sh -d /fs/ssm/hpco/exp/sarrac-2.18.05b4
 
or it may be installed in the system locations (/usr/bin, etc...)


Release Process
---------------

To note changes:
  - Compile once with -DSR_DEBUG_LOGS to verify that no msg_log calls have errors (compiler will report)
  - build package (without -DSR_DEBUG_LOGS) and install.
  - run some ./test scripts.
  - make trust_but_verify
    examine results, which include a valgrind run.
  - Run through a flow test.
  - dch, and add your points.
  - when ready to release, edit UNRELEASED to an appropriate status, usually unstable.
  - git commit #what you need to commit...
  - git tag <release> -m <release>
  - git push
  - git push origin <release>

  - go to Launchpad, and import source `here <https://code.launchpad.net/~ssc-hpc-chp-spc/metpx-sarrac/+git/master>`_.
  - go to launchpad, find the recipe and Request Build `here <https://code.launchpad.net/~ssc-hpc-chp-spc/+recipe/metpx-sarrac>`_.


Building RPMS
-------------

on Suse::

  zypper addrepo https://download.opensuse.org/repositories/network:messaging:amqp/openSUSE_Leap_15.1/network:messaging:amqp.repo
  zypper refresh
  zypper install librabbitmq4 librabbitmq-devel
  zypper install libopenssl-devel libjson-c-devel
  make rpm_suse15

on Redhat/Centos::

  make rpm_rhel7


( notes from: https://github.com/MetPX/sarrac/issues/73 )


Proposed Coding Style Guidelines
--------------------------------

Generally, we used `Linux Kernel C Guidelines <https://www.kernel.org/doc/html/v4.10/process/coding-style.html>`_

but with one pythonic affectation:  You know Rule 1? about the tabs with 8 characters?  This code base is normally
indented like python instead, use four spaces, and not tabs.

Also, in terms of documenting code, when adding new things one should add comments
keeping in minde compatbility with `doxygen <http://www.doxygen.nl/manual/docblocks.html>`_ 
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
useful to document which one was used.   I believe it undoes for the pythonic exception.
