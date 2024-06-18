
------------------------------
Making a Release of MetPX-sr3c
------------------------------

Release Targets:

* hpc: intel and powerpc
* launchpad: whatever platforms it builds for (ARM would be cool.)
* upload packages to github, which acts as central node for release notifications.


Build Dependencies
------------------

The librabbitmq version needs to be > 0.8,  this is newer than what is in
ubuntu 16.04. So you need to git clone from https://github.com/alanxz/rabbitmq-c
then built it there. The launchpad PPA has a backport included to take care of
this::

  export RABBIT_BUILD=*directory where rabbit has been built*

on new OS's, the packaged versions are fine:

* librabbitmq-dev - AMQP client library written in C - Dev Files
* libssl-dev  - OpenSSL client library (used for hash algorithms.)
* libjson-c-dev - json-c header files.

run dependencies::

  librabbitmq4 - AMQP client library written in C
  libssl - OpenSSL client library.
  libjson-c3 - JSON manupulation library (for v03 parsing)

On RPM-based distributions::
  
  librabbitmq-devel
  json-c-devel

This JSON library changed API multiple times in it's history. Metpx-sr3c development
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


Branches
--------

The main repository of sarrac is: https://github.com/MetPX/sarrac
As of 2022/12, development is on v3 compatible version of sarrac.
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

To note changes:
  - update debian/changelog appropriately for the release. 
  - in debian/changelog, Set the version on the first line correctly. This version will determine the label on the built packages, regardless of git tag. (perhaps use dch on debian/ubuntu system.)
  - Compile once with -DSR_DEBUG_LOGS to verify that no msg_log calls have errors (compiler will report)
  - build package (without -DSR_DEBUG_LOGS) and install.
  - make trust_but_verify
    examine results, which include a valgrind run.
  - install package so that it is used for flow tests on at least one platform.
  - find redhat8 (with local disk) and run make test_shim
  - find ubuntu18 (with local disk) and run make test_shim.
  - dch, and touch up your points if need be.
  - when ready to release, edit UNRELEASED to an appropriate status, usually unstable.
  - git commit #what you need to commit...
  - git tag <release> -m <release>
  - git push
  - git push origin <release>

  - go to Launchpad, and import source `here <https://code.launchpad.net/~ssc-hpc-chp-spc/metpx-sarrac/+git/master>`_.
  - go to launchpad, find the recipe and Request Build `here <https://code.launchpad.net/~ssc-hpc-chp-spc/+recipe/metpx-sr3c-pre-release>`_.
  - go to an hpc account (on an intel node)
    * mkdir ~/Sarracenia;  cd ~/Sarracenia
    * git clone https://github.com/MetPX/sarrac metpx-sr3c
    * cd metpx-sr3c
    * make rpm_rhel7 
  - go to a hpc account on a powerpc node
    * cd Sarracenia/metpx-sr3c
    * make clean
    * make rpm_rhel7

The rpm build targets run *rpmbuild* which places the packages in a standard tree in the user account:
~/rpmbuild/RPMS/<arch>/..rpm on each arch the rpm will be created in the appropriate directory.








Building RPMS
-------------

This is the general procedure when building rpms on a system that has never
had an RPM build on it before.
Clone source to metpx-sr3c directory (needed by rpm build rules)::

  git clone https://github.com/MetPX/sarrac metpx-sr3c
  cd sr3c

on Suse::

  zypper addrepo https://download.opensuse.org/repositories/network:messaging:amqp/openSUSE_Leap_15.1/network:messaging:amqp.repo
  zypper refresh
  zypper install librabbitmq4 librabbitmq-devel
  zypper install libopenssl-devel libjson-c-devel
  make rpm_suse15

on Redhat/Centos::

  # install dependencies somehow... unclear in general.
  make rpm_rhel7


( notes from: https://github.com/MetPX/sarrac/issues/73 )

