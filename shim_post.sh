

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

   cat >~/.config/sr3/cpost/local_post.conf  <<EOT

post_broker ${BROKER}
post_exchange ${EXCHANGE}
vip 127.0.0.1
realpath off
logReject on
logLevel debug
debug True
realpathAdjust -2
realpathDirPost True
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

post_baseUrl file:${PWD}

post_topicPrefix v03.post

accept `realpath .`/.*
accept `realpath ${HOME}/test`/.*
reject .*
EOT


   echo "ignore rm errors.. cleaning before start"
   rm hihi 
   rm hoho 
   rm haha 
   rm ~/test/hoho_my_darling.txt 
   rm hoohoo

   export SR_POST_CONFIG=local_post.conf
   if [ "${SYSTEM_SHIM_TEST}" ]; then
       export LD_PRELOAD=libsr3shim.so.1.0.0
    else
       export LD_PRELOAD=`pwd`/libsr3shim.so.1.0.0
       export LD_LIBRARY_PATH=`pwd`:${LD_LIBRARY_PATH}
    fi
   export SR_SHIMDEBUG=99
   exec $0
fi

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
echo "#test 1 sha512 160 stdout redirection in a subdir"
echo "fileone" >>dirone/fileone

echo "#test 1 directory 170 make third directory."
mkdir dirone/dirtwo

echo "#test 1 sha512 180 stdout redirection in a subsubdir"
echo "filetwo" >>dirone/dirtwo/filetwo

echo "#test 1 rename 190 renaming subdirs should cause file rename events."
mv dirone dirthree
echo "#test 2 remove 200 removing a whole tree events."
rm -rf dirthree
echo "#test 2 remove 210 removing two files"
rm hoho hoohoo
echo "#test 0 comment 220 shim test posting end"
echo "#test 0 comment 230 test to ensure previous completes"
