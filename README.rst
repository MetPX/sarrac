
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

will build a package you can install. Otherwise just *make*, and you need
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
items every *sleep* seconds (equivalent to sr3_watch.) 

There is also an LD_PRELOAD shim library. (libsr3shim.c) that uses the posting
API, this is to be used in `very high volume use cases <https://github.com/MetPX/sarracenia/blob/main/doc/hpc_mirroring_use_case.rst>`_

Sample usage::

   export SR_POST_CONFIG="mypost"
   export LD_PRELOAD=`pwd`/libsr3shim.so.1.0.0
   #export SR_POST_READS=true
   #export SR_SHIMDEBUG=99

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
post when the process exits. 

This option does not work with some built-in executables such as cp
and ln, since they seem to use _exit() system call which does not call
any programmed exit processing.

An opposite approach::

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

If the SR_SHIMDEBUG variable is set to an integer value, progressively
more verbose messaging will occur, the higher the integer. messages 
from this setting look like so::

  SR_SHIMDEBUG 2 504576 0.0270023 fclose 0x7fd053a8d780 /home/peter/Sarracenia/metpx-sr3c/shim_test.log status=0

fields present:

  * 2 the level of the message.
  * 504576 pid of the process doing the logging.
  * 0.0270023 elapsed wallclock time of the process since it started (in seconds.)

Lastly, There is also a sample consumer::

  sr3_cpump

which obtains messages and, by default, prints them to standard output in v03
format.

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

NOTE:

  * The posting logic (sr3_cpost and the library) are the focus of the implementation.
    They fully work.

  * The consumer logic in C is functional, but not completely robust.
    It should not be used in operations, but is more of a technology demonstrator.
    It acknowledges receipt of messages before application processing has completed
    ( https://github.com/MetPX/sarrac/issues/121 ) 
   
    We have flow tests demonstrating failure modes and message loss.
    The tests are disabled for now because the C consumer does lose messages.


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


Dorval Computing Centre
-----------------------

If you are in some Dorval computing centre environments, then 
`SSM <https://expl.info/display/SSM>`_ is available and a compatible version
of rabbitmq-c can be obtained ::

  . ssmuse-sh -d /fs/ssm/main/opt/rabbitmqc/rabbitmqc-0.8.0
 
To load sr3_cpost::

  . ssmuse-sh -d /fs/ssm/hpco/exp/sarrac-2.18.05b4
 
or it may be installed in the system locations (/usr/bin, etc...)

Build Process
-------------

See `Building from Source <BUILD.rst>`_


Release Process
---------------

See `Releases <Release.rst>`_
