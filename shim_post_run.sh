set -x

which bash

echo "#test 0 comment 000 shim test posting start"
echo "#test 1 sha512 010 capturing stdout"
bash -c 'echo "hoho" >> ./hoho'

echo "#test 1 sha512 020 c program run."
truncate --size=2 ./hoho

echo "#test 1 sha512 030 python program run"
/usr/bin/python3 pyiotest

grep lovely pyiotest

echo "#test 1 directory 040 make directory"
mkdir sub_dir1

echo "#test 1 rename 050 rename directory"
mv sub_dir1 sub_dir2

echo "#test 1 rmdir 060 remove directory"
rmdir sub_dir2


echo "#test 1 sha512 070 cp command"
cp libsr3shim.c ~/test/hoho_my_darling.txt

echo "#test 1 sha512 080 touch command"
touch hihi

echo "#test 1 link 090 symlink command"
ln -s hoho haha

echo "#test 1 rename 100 moving a symlink"
mv haha hihi

echo "#test 1 rename 110 hardlink to a symlink"
ln hihi hoohoo
echo "#test 1 rename 120 moving a file. "
mv ~/test/hoho_my_darling.txt ~/test/hoho2.log
echo "#test 1 remove 130 removing a file. "
rm hihi

echo "#test 1 remove 140 removing a file." 
rm ~/test/hoho2.log

echo "#test 1 directory 150 make second directory ."

mkdir dirone
if [ "${KNOWN_REDIRECTION_BUG}" ]; then
    echo "#test 1 sha512 160 cp to avoid stdout redirection in a subdir"
    cp hoho dirone/fileone
else
    echo "#test 1 sha512 160 stdout redirection in a subdir"
    echo "fileone" >>dirone/fileone
fi

echo "#test 1 directory 170 make third directory."
mkdir dirone/dirtwo

if [ "${KNOWN_REDIRECTION_BUG}" ]; then
    echo "#test 1 sha512 180 cp to avoid stdout redirection in a subsubdir"
    cp hoho dirone/dirtwo/filetwo
else
    echo "#test 1 sha512 180 stdout redirection in a subsubdir"
    echo "filetwo" >>dirone/dirtwo/filetwo
fi

echo "#test 1 rename 190 renaming subdirs should cause file rename events."
mv dirone dirthree
echo "#test 4 remove 200 removing a whole tree events."
rm -rf dirthree
echo "#test 2 remove 210 removing two files"
rm hoho hoohoo
echo "#test 0 comment 220 shim test posting end"
echo "#test 0 comment 230 test to ensure previous completes"
