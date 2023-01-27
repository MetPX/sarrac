

if [ ! "${SR_POST_CONFIG}" ]; then
   if [ ! -d ~/test ]; then
     mkdir ~/test
   fi
   mkdir -p ~/.config/sr3/cpost

if [ ! "${BROKER}" ]; then
    BROKER=amqp://tfeed@localhost
fi

if [ ! "${EXCHANGE}" ]; then
    EXCHANGE=xs_pastest
fi

DIRECTORY=`pwd`

   cat >~/.config/sr3/cpost/local_post.conf  <<EOT

post_broker ${BROKER}
post_exchange ${EXCHANGE}
vip 127.0.0.1
realpath off
logReject on
logLevel debug
debug True
exchangeDeclare True
#integrity none
shim_post_minterval 10
#shim_skip_parent_open_files
#shim_post_once
#shim_defer_posting_to_exit
expire 1d
nodupe_ttl 0
header toto=pig
events modify,link,delete,mkdir,rmdir

post_baseUrl file:${DIRECTORY}
post_baseDir ${DIRECTORY}

post_topicPrefix v03.post

accept .*
EOT


   echo "ignore rm errors.. cleaning before start"
   rm hihi 
   rm hoho 
   rm haha 
   rm ~/test/hoho_my_darling.txt 
   rm hoohoo

   export SR_POST_CONFIG=local_post.conf
   export LD_PRELOAD=`pwd`/libsr3shim.so.1.0.0
   export LD_LIBRARY_PATH=`pwd`:${LD_LIBRARY_PATH}
   export SR_SHIMDEBUG=99
   exec $0
fi

set -x

which bash

echo "#test 0 comment shim test posting start"
echo "#test 1 sha512 capturing stdout"
bash -c 'echo "hoho" >> ./hoho'

echo "#test 1 sha512 c program run."
truncate --size=2 ./hoho

echo "#test 1 sha512 python program run"
/usr/bin/python3 pyiotest

grep lovely pyiotest

echo "#test 1 directory make directory"
mkdir sub_dir1

echo "#test 1 rename rename directory"
mv sub_dir1 sub_dir2

echo "#test 1 rmdir remove directory"
rmdir sub_dir2


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

echo "#test 1 directory make second directory ."

mkdir dirone
echo "#test 1 sha512 stdout redirection in a subdir"
echo "fileone" >>dirone/fileone

echo "#test 1 directory make third directory."
mkdir dirone/dirtwo

echo "#test 1 sha512 stdout redirection in a subsubdir"
echo "filetwo" >>dirone/dirtwo/filetwo

echo "#test 1 rename renaming subdirs should cause file rename events."
mv dirone dirthree
echo "#test 2 remove removing a whole tree events."
rm -rf dirthree
echo "#test 2 remove removing two files"
rm hoho hoohoo
echo "#test 0 comment shim test posting end"
echo "#test 0 comment test to ensure previous completes"
