
set -x

cd shim_dirA
which bash

echo "FIXME: KNOWN ISSUE redirection close does not get posted!"
#echo "#test 1 sha512 000 capturing stdout"
#bash -c 'echo "hoho" >> ./hoho'

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

echo "#test 1 link 060 symlink command"
ln -s hoho haha


echo lovely day eh

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

if [ "${KNOWN_REDIRECTION_BUG}" ]; then
	echo "#test 1 sha512 120 cp replaces redirection in a subdir"
	cp hoho link_to_dirone/fileone
else
	echo "#test 1 sha512 120 stdout redirection in a subdir"
	echo "fileone" >>link_to_dirone/fileone
fi

if [ "${KNOWN_REDIRECTION_BUG}" ]; then
	echo "#test 1 sha512 120 cp replaces 2nd stdout redirection in a subdir"
	cp hoho link_to_dirone/filefive
else
	echo "#test 1 sha512 120 2nd stdout redirection in a subdir"
	echo "lovely" >>link_to_dirone/filefive
fi

echo "#test 1 directory 130 mkdir 2"
mkdir dirone/dirtwo

echo "#test 1,1 link,rename 135 symlink in a sub-dir"
ln -sf `pwd`/link_to_dirone/fileone dirone/link_to_fileone

if [ "${KNOWN_REDIRECTION_BUG}" ]; then
	echo "#test 1 sha512 140 cp replaces redirection in a subsubdir"
	cp hoho dirone/dirtwo/filetwo
else
	echo "#test 1 sha512 140 stdout redirection in a subsubdir"
	echo "filetwo" >>dirone/dirtwo/filetwo
fi

echo "#test 1 rename 145 rename in a sub-dir"
mv dirone/dirtwo/filetwo dirone/dirtwo/filefour

# sleep to allow copies to happen before renaming directory...
sleep 15 
echo "#test 1 rename 150 renaming subdirs should cause file rename events."
mv dirone dirthree

echo "#test 1 link 135 symlink in a sub-dir"
ln -sf `pwd`/dirthree/dirtwo/filefour dirthree/dirtwo/link2four

if [ "${KNOWN_REDIRECTION_BUG}" ]; then
    echo "#test 1 sha512 141 create test_file (without redirection)"
    cp hoho test_file
else
    echo "#test 1 sha512 142 create test_file with redirection"
    echo  1 >test_file
fi
echo "#test 1 sha512 151 update test_file"
touch test_file

echo "#test 1 rename 152 move test_file into dirthree subdir"
mv test_file dirthree

if [ "${KNOWN_REDIRECTION_BUG}" ]; then
    echo "#test 1 sha512 161 create test_file (again)"
    cp dirthree/test_file test_file
else
    echo "#test 1 sha512 162 create test_file (again)"
    echo 2 >test_file
    echo "#no post from touch, refused as repeat"
    touch test_file
fi

echo "#test 1 rename move test_file into dirthree subdir (new name)"
mv test_file dirthree/new_test_file

echo "#test 0 comment 160 shim copy posting end"
