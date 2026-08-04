# Test some known cases that can trigger race conditions/order of 
# operations problems. 
# Related issues:
# 	sarracenia #1395
# 	sarracenia #1366
# 	sarracenia #1297
#       sarrac #174

set -x

cd shim_dirA
which bash

echo "#test 0 comment 010 shim copy posting start"

echo "#test 1 sha512 000 capturing stdout"
echo "hoho" >> ./hoho

echo "#test 1 sha512 c program run."
truncate --size=2 ./hoho

echo "#test 1 sha512 020 python program run"
/usr/bin/python3 ../pyiotest

grep lovely pyiotest

echo "#test 1 sha512 030 cp command"
cp ../libsr3shim.c hoho_my_darling.txt

echo "#test 1 sha512 040 cp command2"
cp ../libsr3shim.c file_to_delete

#echo "#test 1 hlink 050 hard link command"
#ln hoho hard_link_to_hoho

echo "#test 1 link 050 symlink to a broken place"
ln -sf broken_do_not_exist symlink_to_non_existent_place

# (re-) creating a symlink that already exists should generate two messages
# one link with a temporary name and one rename that renames the temporary name to the
# correct name, and overwrites the already existing symlink in the process

echo "#test 1,1 link,rename 050 symlink to a broken place"
ln -sf broken_do_not_exist symlink_to_non_existent_place

#echo "#test 1 link 050 symlink to a broken place"
#ln -sf `pwd`/broken_do_not_exist2 `pwd`/symlink_to_non_existent_place2

echo "#test 1 link 060 symlink to existing place"
ln -s file_to_delete link_to_file_to_delete




echo "#test 1 directory 100 mkdir 1"
mkdir dirone

echo "#test 1 sha512 120 stdout redirection in a subdir"
echo "fileone" >>dirone/fileone

echo "#test 1 sha512 120 2nd stdout redirection in a subdir"
echo "lovely" >>dirone/fileabcd

echo "#test 1 link 120 symlink inside dir"
ln -s dirone/fileone dirone/link_to_fileone

echo "#test 1 rename 120 rename fileone to filetwo"
mv dirone/fileone dirone/filetwo

# wait to ensure file copies finish
sleep 20

# expect 4 messages: 3 for the contents being deleted and 1 for the directory itself (should be last)
echo "#test 4 remove 130 remove non-empty directory"
rm -rf dirone




echo "#test 0 comment 160 shim copy posting end"
