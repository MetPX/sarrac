# based on shim_copy_mirror_sftp.sh

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

# to force retries to be processed more quickly
housekeeping 30s

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

post_baseUrl sftp://${USER}@localhost/`realpath $(pwd)`/shim_dirA
post_topicPrefix v03.post

accept `realpath .`/.*
accept `realpath ${HOME}/test`/.*
reject .*
EOT

mkdir -p ~/.config/sr3/plugins
cat >~/.config/sr3/plugins/screw_up_order.py  <<EOT

import logging
from sarracenia.flowcb import FlowCB

logger = logging.getLogger(__name__)

class Screw_up_order(FlowCB):
    """ for testing shim: re-order certain events to simulate race conditions

        CASE A: overwriting a symlink that already exists results in two posts:
            1) symlink temporary name (Cfdsfadsa) to correct destination (fileOp link)
            2) rename temporary symlink to desired_name, overwriting the old file/symlink
               named desired_name in the process (fileOp link + rename)

            re-order worklist so that link+rename fileOp events come before just link
            example messages:
                2025-04-02 20:58:15,394 [INFO] shim published: { "pubTime":"20250402205815.39313447", "baseUrl":"file:/fs/home/ras000/metpx-sr3c-3.25.03rc3-x64/shim_dirA", "relPath":"CucZxOOZ", "topic":"v03.post", "toto":"pig", "fileOp" : { "link":"../libsr3shim.c"}}

                2025-04-02 20:58:15,395 [INFO] shim published: { "pubTime":"20250402205815.39473321", "baseUrl":"file:/fs/home/ras000/metpx-sr3c-3.25.03rc3-x64/shim_dirA", "relPath":"file_to_delete", "topic":"v03.post", "toto":"pig", "fileOp" : { "link":"../libsr3shim.c", "rename" : "/fs/home/ras000/metpx-sr3c-3.25.03rc3-x64/shim_dirA/CucZxOOZ" }}

        CASE B: directory removal - first all the files and subdirectories are deleted, then
            the directory gets deleted. If the final remove message is processed before all the
            files and subdirectories are deleted, the rmdir will fail (because the dir is not empty).

            This re-orders the messages to ensure that the directory removal is always attempted before
            the directory is empty.


    """

    def __init__(self, options):
        super().__init__(options, logger)
        self.delayed_link = []
        self.delayed_remove = []
        self.new_delayed_link = []
        self.new_delayed_remove = []

        # how many batches to delay before putting the delayed messages back in
        self.o.add_option('delay_batches', 'count', default_value=10)
        self.batch_count = 0

    def after_accept(self, worklist):
        new_incoming = []
        for msg in worklist.incoming:
            # don't interfere with retries and non-fileOps
            if ('_isRetry' in msg and msg['_isRetry']) or 'fileOp' not in msg:
                new_incoming.append(msg)
                continue
            # fileOps
            else:
                # delay links so the link+rename gets handled first
                if 'link' in msg['fileOp'] and 'rename' not in msg['fileOp']:
                    self.new_delayed_link.append(msg)
                    logger.info(f"delaying link msg: {msg}")
                # delay non-directory removes; this will cause directory removes to be attempted first
                elif 'remove' in msg['fileOp'] and 'directory' not in msg['fileOp']:
                    self.new_delayed_remove.append(msg)
                    logger.info(f"delaying non-directory remove msg: {msg}")
                else:
                    new_incoming.append(msg)

        worklist.incoming = new_incoming

        self.batch_count +=1

        # put the delayed messages from last batch into this batch
        if self.batch_count >= self.o.delay_batches:
            logger.info(f"releasing delayed messages ({len(self.delayed_link)} links, {len(self.delayed_remove)} removes)")
            worklist.incoming.extend(self.delayed_link)
            worklist.incoming.extend(self.delayed_remove)
            self.delayed_link = self.new_delayed_link
            self.delayed_remove = self.new_delayed_remove
            self.new_delayed_link = []
            self.new_delayed_remove = []
            self.batch_count = 0

EOT

echo "callback screw_up_order" >> ~/.config/sr3/default.conf

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

# run in a new shell to ensure output redirection correctly triggers posts #177
#bash ./shim_copy_post2.sh &
bash ./shim_copy_race_conditions.sh &

unset SR_POST_CONFIG
unset SR_SHIMDEBUG
unset LD_PRELOAD
wait


# job step 2... copy.
sleepytime=15
echo "waiting ${sleepytime} seconds for copies to complete"
sleep ${sleepytime}

sr3 remove cpost/local_post.conf

# wait for retries to finish before stopping subscriber
./test_util/wait_for_retries.sh

# wait a bit longer
sleep 60

sr3 stop subscribe/local_copy.conf
sr3 remove subscribe/local_copy.conf

rm ~/.config/sr3/plugins/screw_up_order.py

sed -i '/callback screw_up_order/d' ~/.config/sr3/default.conf

echo "#test 0 comment comparing trees"

./test_util/compare_trees.sh --check-links
echo
