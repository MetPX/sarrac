/*! \mainpage Sarrac 


## Introduction ##


A partial implementation of a Sarracenia client in C. 
It does all the AMQP parts, but none of the other protocols (used for actual downloads.)
The functionality is not intended to be a complete implementation, it is 
just a few pieces meant to provide interoperability for
cases where either a python3 environment is either impractical, or where there
are performance concerns that this implementation would help with. Examples:

 - in some environments getting python3 environment installed is hard
    (example: cray linux environment is a software environment from circa 2009)
 
 - in-process invocation of sr_post on file closes (libsrshim.)

## More ##

See README.rst for more information.

## This File ##

This file is doxymain.md, a stub.  FIXME: 

 - get doxygen to grok restructuredtext ?

 - why is the title still *My Project* ? 

