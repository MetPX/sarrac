
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

A library, libsarra is built, with external interfaces one can access from C 
using the entry points and data structures documented in sr_context.h, sr_post.h, 
and sr_consume.h files.  The library uses sr_config(7) style config files (see Limitations). 
A sample usage of the libraries is a command line binary, that can call the library::

   sr_cpost

This function takes the same options as sr_post, but the *sleep* argument, 
when supplied causes it to loop, checking for new items every *sleep* seconds 
(equivalent to sr_watch.) There is also a sample consumer::

  sr_cpump

which obtains messages and, by default, prints them to standard output in json format identical
the the format used by the python implementation for save/restore.
In order to have a complete downloader, one needs a script to parse the json output
and invoke an appropriate binary downloader.  One can use the 'outlet' switch
to choose other formats:
 
json:
  the default format, json compatible with python save/restore.

post:
  turns sr_cpump into an sr_shovel, if cache is on, then it is a winnow.

url: 
  just print out the retrieval urls, rather than the entire message



There is also an LD_PRELOAD shim library example. (libsrshim.c) that
uses the posting api. sample usage::

   export SR_POST_CONFIG="mypost"
   export LD_PRELOAD=`pwd`/libsrshim.so.1.0.0
   #export SR_POST_READS=true
   #export SR_SHIMDEBUG=true 

   cp libsrshim.c ~/test/hoho_my_darling.txt
   ln -s hoho haha
   rm haha

With the SR_POST_CONFIG set to "mypost", The libsrshim library will look in ~/.config/sarra/post/  for "mypost.conf."
With the LD_PRELOAD set to use the library, processes that run will call functions like 'close' that are in 
the shim library, and the shim library will apply the "mypost.conf" configuration to figure out whether it
should post the file being closed, and if so, to what broker.  

Normally, posting  will only occur for files that have been written. If one wants to post files opened even in
readonly mode, this triggers more overhead as even trivial programs such as *cat* need to configure a connection
to the broker in case they end up posting to it. Normally, the connection is only established when there
is a modified file is checked for posting. To enable full access monitoring, set the SR_POST_READS variable.
This provides an auditing function and/or the ability to mirror a complete environment (even files that we didn't
know we needed.)

If the SR_SHIMDEBUG variable is set, rather verbose messaging will occur.



Limitations of the C implementation
-----------------------------------

 - This library and tools do not work with any plugins from the python implementation.
 - This library is a single process, the *instances* setting is completely ignored.
 - The queue settings established by a consumer are not the same as those of the python
   implementation, so queues cannot be shared between the two.
 - The C is infected by python taste... 4 character indent, with spaces, all the time.


Build Dependencies
------------------

The librabbitmq version needs to be > 0.8,  this is newer than what is in ubuntu 16.04.
So you need to git clone from https://github.com/alanxz/rabbitmq-c  ... then built it there.


export RABBIT_BUILD=*directory where rabbit has been built*


librabbitmq-dev - AMQP client library written in C - Dev Files
libssl-dev  - OpenSSL client library (used for hash algorithms.)

run dependencies:
librabbitmq4 - AMQP client library written in C
libssl - OpenSSL client library.


  

Dorval Computing Centre
-----------------------

If you are in the Dorval computing centre environment, then SSM is available and 
a compatible version of rabbitmq-c can be obtained 

. ssmuse-sh -d /fs/ssm/main/opt/rabbitmqc/rabbitmqc-0.8.0
 
To load sr_cpost
. ssmuse-sh -d /fs/ssm/hpco/exp/sarrac-0.5
 


Plan:
  - figure out packaging?
  - if the local shim does not go well, step 2 is: sr_cwatch.


Developer Notes
---------------



whereami:
  - partitioned (partflg='p') files, not implemented, see pseudo-code in sr_post.c

  - FIXME: when 'start' if sleep <= 0 , should exit (not an error, compatibility with sr start all configs)

  - FIXME: require a configuration file (log & state files) ?  sr_subscribe does work without it, but result is
    often surprising for the user.

worries/notes to self:

  - behaviour on posting and empty file results in a partstr 1,0,1,0,0
    partstrategy=1 (whole file), blocksize=0, blockcount=1, remainder=0, block=0.
    does that mean subscribers should try to download 0 bytes ? ... wondering if there 
    is something to do.  Should look at subscribers and confirm they do something sane.
 
Release Process
---------------

Packages are only available for Ubuntu 17.10 and 18.04 as they have the version (>=0.8.0) of librabbitmq-c 
that sarrac needs 

To note changes:
  - dch, and add your points.
  - when ready to release, edit UNRELEASED to an appropriate status, usually unstable.
  - go to Launchpad, and import source.
  - go to launchpad, find the recipe and Request Build



