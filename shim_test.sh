

if [ ! "${SR_POST_CONFIG}" ]; then
   if [ ! -d ~/test ]; then
     mkdir ~/test
   fi

   echo "ignore rm errors.. cleaning before start"
   rm hihi 
   rm hoho 
   rm haha 
   rm ~/test/hoho_my_darling.txt 
   rm hoohoo

   export SR_POST_CONFIG=`pwd`/local_post.conf
   export LD_PRELOAD=`pwd`/libsr3shim.so.1.0.0
   export LD_LIBRARY_PATH=`pwd`:${LD_LIBRARY_PATH}
   export SR_SHIMDEBUG=99
   exec $0
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

echo "#test 1 sha512 touch command"
touch hihi

echo "#test 1 link symlink command"
ln -s hoho haha

echo "#test 1 rename moving a symlink"
mv haha hihi

echo "#test 1 rename hardlink to a symlink"
ln hihi hoohoo
echo "#test 1 rename moving a file. "
mv ~/test/hoho_my_darling.txt ~/test/hoho2.log
echo "#test 1 remove removing a file. "
rm hihi

echo "#test 1 remove removing a file." 
rm ~/test/hoho2.log


mkdir dirone
echo "#test 1 sha512 stdout redirection in a subdir"
echo "fileone" >>dirone/fileone
mkdir dirone/dirtwo

echo "#test 1 sha512 stdout redirection in a subsubdir"
echo "filetwo" >>dirone/dirtwo/filetwo

echo "#test 2 rename renaming subdirs should cause file rename events."
mv dirone dirthree
echo "#test 2 remove removing a whole tree events."
rm -rf dirthree
echo "#test 2 remove removing two files"
rm hoho hoohoo
echo "#test 0 last test to ensure previous completes"
