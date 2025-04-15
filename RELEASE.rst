
------------------------------
Making a Release of MetPX-sr3c
------------------------------

Release Targets:

* hpc: intel and powerpc
* launchpad: whatever platforms it builds for (ARM would be cool.)
* upload packages to github, which acts as central node for release notifications.

* See `Build <BUILD.rst>`_ for instructions on local building.

Pre-Release QA/Validation
-------------------------

Finalize the changes:

  - update debian/changelog appropriately for the release. 
  - in debian/changelog, Set the version on the first line correctly. This version will determine the label on the built packages, regardless of git tag. (perhaps use dch on debian/ubuntu system.)
  - Compile once with -DSR_DEBUG_LOGS to verify that no msg_log calls have errors (compiler will report)
  - make trust_but_verify
    examine results, which include a valgrind run.

Once that is clean, proceed to the Pre-Release Porting:

Pre-Release Porting
~~~~~~~~~~~~~~~~~~~

Development is mostly done on new operating systems. The most important platforms
for deployment, however, are fairly old.

Prior to doing a full release, should install on all platforms and run tests. on Github,
these tests are done by Actions automatically, so one just has to review results for
ubuntu 20.04, 22.04, and 24.04.  However one must run the tests manually on the following
platforms:

for each of:

* redhat8 
* redhat9
* ubuntu18

do:

* https://github.com/MetPX/sarrac/blob/development/BUILD.rst#testing
* then install the package locally: either
   
   * https://github.com/MetPX/sarrac/blob/development/BUILD.rst#build-a-debian-package  or 
   * https://github.com/MetPX/sarrac/blob/development/BUILD.rst#build-a-debian-package

* install them... 

   * rpm -ivh or dpkg -i ...

* then run the python flow_tests. as per the python package documentation:

  * https://metpx.github.io/sarracenia/Contribution/Release.html#pre-release-overview

Pre-Release Packaging:
^^^^^^^^^^^^^^^^^^^^^^

Assuming the ``debian/changelog`` has already been updated and committed to the development branch, and that the testing steps above have been completed successfully::

  git checkout development
  git pull
  git checkout pre-release
  git pull
  git merge --strategy-option=theirs development
  git push
  git tag -a v3.yy.mm.rcZ -m "pre-release v3.yy.mm.rcZ"
  git push origin v3.yy.mm.rcZ
  
* go to Launchpad, and import source `here <https://code.launchpad.net/~ssc-hpc-chp-spc/metpx-sarrac/+git/master>`_.
* go to Launchpad, find the recipe and Request Builds `here <https://code.launchpad.net/~ssc-hpc-chp-spc/+recipe/metpx-sr3c-pre-release>`_.
* `Build RPM Packages`_ using the ``pre-release`` branch (repeat for both RedHat 8 and RedHat 9)
* Create a new release on GitHub: https://github.com/MetPX/sarrac/releases/new 

  * Upload the RPM packages


Release Process
---------------

To note changes:

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
- go to launchpad, find the recipe and Request Build `here <https://code.launchpad.net/~ssc-hpc-chp-spc/+recipe/metpx-sr3c>`_.

Build RPM Packages
-------------------

- go to an hpc account (on an intel node)
  
  .. code-block:: console
  
    mkdir ~/Sarracenia;  cd ~/Sarracenia
    git clone https://github.com/MetPX/sarrac.git metpx-sr3c
    
    # NOTE: the directory must be named metpx-sr3c
    cd metpx-sr3c
    git checkout $BRANCH_YOU_WANT
    make rpm_rhel7 
    
    # To install it:
    rpm -ivh ~/rpmbuild/RPMS/_platform_/*version*.rpm  (if upgrading, -Uvh)

- go to a hpc account on a powerpc node

  .. code-block:: console

    cd Sarracenia/metpx-sr3c
    make clean
    make rpm_rhel7
    rpm -ivh ~/rpmbuild/RPMS/_platform_/*version*.rpm

The rpm build targets run *rpmbuild* which places the packages in a standard tree in the user account:
~/rpmbuild/RPMS/<arch>/..rpm on each arch the rpm will be created in the appropriate directory.


