
rm -r -f ~/test/hoho 2> /dev/null

if [ ! "${SR_POST_CONFIG}" ]; then
   export SR_POST_CONFIG=`pwd`/test_post.conf
   export LD_PRELOAD=`pwd`/libsr3shim.so.1.0.0
   exec $0
fi

set -x

'echo "hoho" >>~/test/hoho'
