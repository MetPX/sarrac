

if [ ! "${SR_POST_CONFIG}" ]; then
   export SR_POST_CONFIG=`pwd`/local_post.conf
   export LD_PRELOAD=`pwd`/libsr3shim.so.1.0.0
   exec $0
fi

if [ ! -d ~/test ]; then
  mkdir ~/test
fi
set -x

which bash

echo "FIXME: KNOWN ISSUE redirection close does not get posted!"
echo "#test 1 sha512 capturing stdout"
bash -c 'echo "hoho" >> ./hoho'

echo "#test 1 sha512 c program run."
truncate --size=2 ./hoho

echo "#test 1 sha512 python program run"
/usr/bin/python2.7 pyiotest
grep lovely pyiotest

echo "#test 1 sha512 cp command"
cp libsr3shim.c ~/test/hoho_my_darling.txt
echo "#test 1 n touch command"
touch hihi
echo "#test 1 link symlink command"
ln -s hoho haha
echo "#test 1 link moving a symlink"
mv haha hihi
echo "#test 1 hardlink hardlink to a symlink
ln hihi hoohoo
echo "#test 1 sha512 moving a file. "
mv ~/test/hoho_my_darling.txt ~/test/hoho2.log
echo "#test 1 remove removing a file. 
rm hihi

echo "#test 1 remove removing a file." 
rm ~/test/hoho2.log
mkdir dirone
echo "#test 1 sha512 stdout redirection in a subdir
echo "fileone" >>dirone/fileone
mkdir dirone/dirtwo
echo "#test 1 sha512 stdout redirection in a subsubdir"
echo "filetwo" >>dirone/dirtwo/filetwo
echo "#test 1 sha512 renaming subdirs should cause file rename events.
mv dirone dirthree
echo "#test 1 sha512 removing a whole tree events."
rm -rf dirthree
echo "#test 2 remove removing two files"
rm hoho hoohoo
echo "#test 0 last test to ensure previous completes"
