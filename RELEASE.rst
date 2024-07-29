
------------------------------
Making a Release of MetPX-sr3c
------------------------------

Release Targets:

* hpc: intel and powerpc
* launchpad: whatever platforms it builds for (ARM would be cool.)
* upload packages to github, which acts as central node for release notifications.

* See `Build <Build.rst>`_ for instructions on local building.

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

  - on redhat8, edit Makefile to add -DINTERCEPT_SYSCALL to CFLAGS.

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
    * edit Makefile to add -DINTERCEPT_SYSCALL to CFLAGS.
    * cd metpx-sr3c
    * make rpm_rhel7 
  - go to a hpc account on a powerpc node
    * cd Sarracenia/metpx-sr3c
    * make clean
    * make rpm_rhel7

The rpm build targets run *rpmbuild* which places the packages in a standard tree in the user account:
~/rpmbuild/RPMS/<arch>/..rpm on each arch the rpm will be created in the appropriate directory.


