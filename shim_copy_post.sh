
set -x

cd shim_dirA
which bash

echo "#test 1 sha512 000 capturing stdout"
echo "hoho" >> ./hoho

echo "#test 0 comment 010 shim copy posting start"
echo "#test 1 sha512 c program run."
truncate --size=2 ./hoho

echo "#test 1 sha512 020 python program run"
/usr/bin/python3 ../pyiotest

grep lovely pyiotest

echo "#test 1 sha512 030 cp command"
cp ../libsr3shim.c hoho_my_darling.txt

echo "#test 1 sha512 040 cp command2"
cp ../libsr3shim.c file_to_delete
echo "#test 1 sha512 050 touch command"
touch hihi

echo "#test 1 hlink 050 hard link command"
ln hoho hard_link_to_hoho



echo "#test 1 link 060 symlink command"
ln -s hoho haha

echo "#test 1 link 050 symlink to a broken place"
ln -sf broken_do_not_exist symlink_to_non_existent_place


echo "#test 1 rename 070 moving a symlink"
mv haha hihi

# the testing framework cannot handle expecting two links of different types for one event.
#  uncomment if you want to manually test this use case.
echo "#test 1,1 link,rename symlink -f to existing file... creates two posts: symlink to tmp name, and subsquent rename"
ln -sf ../libsr3shim.c file_to_delete

#echo "#test 1 rename hardlink to a symlink"
#ln hihi hoohoo
echo "#test 1,1 link,rename symlink -f absolute existing file... creates two posts: symlink to tmp name, and subsquent rename"
ln -sf `pwd`/../libsr3shim.c `pwd`/2nd_file_to_delete

echo "#test 1 rename 080 moving a file. "
mv hoho_my_darling.txt hoho2.log

echo "#test 1 remove 090 removing a file." 
rm hoho2.log


echo "#test 1 directory 100 mkdir 1"
mkdir dirone

echo "#test 1 link 110 symlink to directory"
ln -s dirone link_to_dirone

echo "#test 1 sha512 120 stdout redirection in a subdir"
echo "fileone" >>link_to_dirone/fileone

echo "#test 1 sha512 120 2nd stdout redirection in a subdir"
echo "lovely" >>link_to_dirone/filefive

echo "#test 1 directory 130 mkdir 2"
mkdir dirone/dirtwo

echo "#test 1,1 link,rename 135 symlink in a sub-dir"
ln -sf `pwd`/link_to_dirone/fileone dirone/link_to_fileone

echo "#test 1 sha512 140 stdout redirection in a subsubdir"
echo "filetwo" >>dirone/dirtwo/filetwo

echo "#test 1 sha512 160 copy a file to one with spaces in the name"
cp dirone/dirtwo/filetwo "dirone/filetwo copy with spaces in the name"

echo "#test 1 sha512 160 copy a file with spaces in the name (both source and dest)"
cp "dirone/filetwo copy with spaces in the name" "dirone/second spaced file"

# sleep to allow filetwo to be downloaded before renaming it to filefour
sleep 10
echo "#test 1 rename 145 rename in a sub-dir"
mv dirone/dirtwo/filetwo dirone/dirtwo/filefour

# sleep to allow copies to happen before renaming directory...
sleep 15 
echo "#test 1 rename 150 renaming subdirs should cause file rename events."
mv dirone dirthree

echo "#test 1 link 135 symlink in a sub-dir"
ln -sf `pwd`/dirthree/dirtwo/filefour dirthree/dirtwo/link2four

echo "#test 1 sha512 142 create test_file with redirection"
echo  1 >test_file
echo "#test 1 sha512 151 update test_file"
touch test_file

echo "#test 1 rename 152 move test_file into dirthree subdir"
mv test_file dirthree

# sleep to ensure that shim_post_minterval doesn't suppress the post of test_file
sleep 10

echo "#test 1 sha512 162 create test_file (again) using redirection"
echo 2 >test_file

# doing both redirection and touch produces two posts
#if [ ! "${KNOWN_REDIRECTION_BUG}" ]; then
#    echo "#no post from touch, refused as repeat"
#    touch test_file
#fi

echo "#test 1 rename move test_file into dirthree subdir (new name)"
mv test_file dirthree/new_test_file

# issue #208 rm directory with trailing slash
echo "#test 1 directory create without trailing slash"
mkdir dir_test

echo "#test 1 remove directory with trailing slash"
rm -r dir_test/

echo "#test 1 directory create with trailing slash"
mkdir dir_test2/

echo "#test 1 remove directory with trailing slash"
rm -r dir_test2/

echo "#test 0 comment 160 shim copy posting end"
