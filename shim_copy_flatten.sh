
VERSION=`head -1 debian/changelog| sed 's/.*(//' | sed 's/).*//'`
MAJOR_VERSION=`echo \"${VERSION}\" | sed 's+\..*++g'`


# job step 0 - setup...
if [ ! -d ~/test ]; then
     mkdir ~/test
fi

echo "ignore rm errors.. cleaning before start"
rm -rf shim_dirA/ shim_dirB/

for d in shim_dirA shim_dirB shim_dirC; do
        if [ -d $d ]; then
            echo "ignore rm -rf $d"
            rm -rf $d
        fi
        mkdir $d
done 

# symlink between directories out of tree.
ln -s ../shim_dirA/dirthree  shim_dirC/thedir

mkdir -p ~/.config/sr3/subscribe
mkdir -p ~/.config/sr3/cpost

#cp local_copy.conf ~/.config/sr3/subscribe

if [ ! "${BROKER}" ]; then
    BROKER=amqp://tfeed@localhost
fi
if [ ! "${EXCHANGE}" ]; then
    EXCHANGE=xs_feed
fi

cat >~/.config/sr3/subscribe/local_copy.conf <<EOT

broker ${BROKER}
exchange ${EXCHANGE}
messageDebugDump on
topicPrefix v03.post
subtopic #
logReject on
logLevel debug
debug True
expire 10m
nodupe_ttl 0
logMessageDump on
callback log
batch 1
mirror True
flatten _
directory `pwd`/shim_dirB
accept .*`realpath .`/.*
accept .*`realpath ${HOME}/test`/.*
reject .*
#accept .*

EOT

#cp local_post.conf ~/.config/sr3/cpost
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
realpathFilter on
realpathPost on
realpathAdjust -1
expire 1d
nodupe_ttl 0
header toto=pig
events modify,link,delete,mkdir,rmdir

post_baseUrl file:`pwd`/shim_dirA
post_topicPrefix v03.post

accept `realpath .`/.*
accept `realpath ${HOME}/test`/.*
reject .*
EOT

sr3 declare cpost/local_post
sr3 declare subscribe/local_copy
sr3 start subscribe/local_copy.conf

export SR_POST_CONFIG=local_post.conf
if [ "${SYSTEM_SHIM_TEST}" ]; then
   export LD_PRELOAD=libsr3shim.so.${VERSION}
else
   export LD_PRELOAD=`pwd`/libsr3shim.so.${VERSION}
   export LD_LIBRARY_PATH=`pwd`:${LD_LIBRARY_PATH}
fi
export SR_SHIMDEBUG=99
if [ "${KNOWN_REDIRECTION_BUG}" ]; then
     bash ./shim_copy_post.sh &
else
     ./shim_copy_post.sh &
fi
     
unset SR_POST_CONFIG
unset SR_SHIMDEBUG
unset LD_PRELOAD
wait


# job step 2... copy.
sleepytime=15
echo "waiting ${sleepytime} seconds for copies to complete"
sleep ${sleepytime}

sr3 remove cpost/local_post.conf
sr3 stop subscribe/local_copy.conf
sr3 remove subscribe/local_copy.conf

echo "#test 0 comment comparing trees"
    
    
cd shim_dirA
find -H . -type f | xargs md5sum >../dirA.sums
cd ../shim_dirB
find -H . -type f | xargs md5sum >../dirB.sums
cd ..
    
diffs="`diff dirA.sums dirB.sums| wc -l`"

if [ "${diffs}" -eq 0 ]; then
       echo "RESULT: Good! trees the same"
else
       echo "RESULT: BAD trees have $diffs differences"
fi
