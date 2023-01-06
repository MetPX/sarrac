#!/usr/bin/env python3

import json
import sys

bad = 0
good = 0
post_count = {}
tests = 0

# by default run through all and print summary at end.
# with this option, exit on first failed test.

exit_on_bad = (len(sys.argv) >= 3) and sys.argv[2] == 'exit_on_bad'

test_algo = None
test_actual_posts={}
test_post_count = {}

with open(sys.argv[1], 'r') as log:
    l = log.readlines()
    #print(l)
    for i in l:

        line = i.split()
      
        if (i[0] == '+') and line[1] != 'echo':
            print(i)
            continue

        if len(line) < 4:
            continue

        if line[0] == 'RESULT:' :
            print(i)
            if line[1] == 'Good!':
                good += 1
            else:
                bad +=1

            continue

        # sample
        # 2022-12-15 09:54:30,666 [DEBUG] post_broker: amqp://tfeed:<pw>@localhost:5672

        #skip lines like this:
        #  ++ truncate --size=2 ./hoho
        if line[0] == '#test':
            tests += 1
            if test_algo:  # finish previous test...

                if len(test_actual_posts) == 0:
                    if 'comment' in test_post_count:
                        print ( f"RESULT: comment {test_description}" )
                        tests -= 1
                    else:
                        print( f"RESULT: BAD! missing expected {test_post_count} for {test_description}" )
                        bad += 1

                for m in test_actual_posts:
                    if m in test_post_count and (test_post_count[m]
                                                 == test_actual_posts[m]):
                        print(
                            f"RESULT: Good! {test_post_count[m]} {m} posts from {test_description}. as expected"
                        )
                        good += 1
                    else:
                        print(
                            f"RESULT: BAD! {test_actual_posts[m]} {m} posts, expected: {test_post_count} for {test_description}"
                        )
                        bad += 1

                if bad and exit_on_bad:
                    sys.exit(1)

            #print( f"setting: {line} " )
            test_algo = line[2]

            test_post_count = {}
            test_post_count[test_algo] = int(line[1])

            test_description = ' '.join(line[3:])
            test_actual_count = 0
            test_actual_posts = {}

        if line[2] == "[INFO]" and line[3] == 'published:':
            print(i)
            # 2022-12-15 09:54:30,677 [INFO] published: 20221215145430.676464601 sftp://peter@localhost /home/peter/Sarracenia/metpx-sr3c/hoho topic=v03.post.home.peter.Sarracenia.metpx-sr3c sum=n,ac837d7b87a8ca12f0343401d66d081d source=tfeed to_clusters=localhost from_cluster=localhost mtime=20221215145430.67089267 atime=20221215145430.658892516 mode=0664 parts=1,5,1,0,0 toto=pig
            message=json.loads( i[42:] )
            #print( f"message is: {message} " )

            if 'fileOp' in message:
                if 'rename' in message['fileOp']:
                    sum_algo='rename'
                else:
                    sum_algo = list(message['fileOp'].keys())[0] 
            else:
                sum_algo = message['integrity']['method']

            if sum_algo in test_actual_posts:
                test_actual_posts[sum_algo] += 1
            else:
                test_actual_posts[sum_algo] = 1

            if sum_algo in post_count:
                post_count[sum_algo] += 1
            else:
                post_count[sum_algo] = 1

    print(f"posts: {post_count}")

    print(f"RESULT: summary: good: {good}, bad {bad}, total {tests}")

    if bad:
        sys.exit(bad)
    if good < (tests):
        sys.exit(tests - good)

    sys.exit(0)
