
set -x

cd shim_dirA
which bash

echo "FIXME: KNOWN ISSUE redirection close does not get posted!"
echo "#test 1 sha512 capturing stdout"
bash -c 'echo "hoho" >> ./hoho'

echo "#test 0 comment shim copy posting start"
echo "#test 1 sha512 c program run."
truncate --size=2 ./hoho

echo "#test 1 sha512 python program run"
/usr/bin/python3 ../pyiotest

grep lovely pyiotest

echo "#test 1 sha512 cp command"
cp ../libsr3shim.c hoho_my_darling.txt

echo "#test 1 sha512 cp command2"
cp ../libsr3shim.c file_to_delete
echo "#test 1 sha512 touch command"
touch hihi

echo "#test 1 link symlink command"
ln -s hoho haha

echo "#test 1 rename moving a symlink"
mv haha hihi

# the testing framework cannot handle expecting two links of different types for one event.
#  uncomment if you want to manually test this use case.
#echo "#test 1 link symlink -f to existing file... creates two posts: symlink to tmp name, and subsquent rename"
#ln -sf ../libsr3shim.c file_to_delete

#echo "#test 1 rename hardlink to a symlink"
#ln hihi hoohoo
echo "#test 1 rename moving a file. "
mv hoho_my_darling.txt hoho2.log

echo "#test 1 remove removing a file." 
rm hoho2.log


mkdir dirone
echo "#test 1 sha512 stdout redirection in a subdir"
echo "fileone" >>dirone/fileone
#mkdir dirone/dirtwo

#echo "#test 1 sha512 stdout redirection in a subsubdir"
#echo "filetwo" >>dirone/dirtwo/filetwo

#echo "#test 2 rename renaming subdirs should cause file rename events."
#mv dirone dirthree
#echo "#test 0 last test to ensure previous completes"

echo "#test 0 comment shim copy posting end"
