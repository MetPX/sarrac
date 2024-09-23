
VERSION=`head -1 debian/changelog| sed 's/.*(//' | sed 's/).*//'`
MAJOR_VERSION=`echo \"${VERSION}\" | sed 's+\..*++g'`

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

post_baseUrl file:/

post_topicPrefix v03.post

accept `realpath .`/.*
accept `realpath ${HOME}/test/.*`
accept ${HOME}/test/.*
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
	   export LD_PRELOAD=libsr3shim.so.${VERSION}
    else
       export LD_PRELOAD=`pwd`/libsr3shim.so.${VERSION}
       export LD_LIBRARY_PATH=`pwd`:${LD_LIBRARY_PATH}
    fi
   export SR_SHIMDEBUG=99
   exec $0
fi

if [ "${KNOWN_REDIRECTION_BUG}" ];then
    bash ./shim_post_run.sh
else
    . ./shim_post_run.sh
fi


