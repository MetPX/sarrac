#!/usr/bin/env python3

import sys

with open( sys.argv[1], 'r') as log:
   l = log.readlines()
   print(l)
   post_count={}
   for i in l:
      line = i.split()

      if len(line) < 4:
         continue

      # sample
      # 2022-12-15 09:54:30,666 [DEBUG] post_broker: amqp://tfeed:<pw>@localhost:5672

      #skip lines like this:
      #  ++ truncate --size=2 ./hoho
      if line[0] == '#test':
         print( f"setting: {line} " )

      if line[3] == 'published:' :
         print(i)
         # 2022-12-15 09:54:30,677 [INFO] published: 20221215145430.676464601 sftp://peter@localhost /home/peter/Sarracenia/metpx-sr3c/hoho topic=v03.post.home.peter.Sarracenia.metpx-sr3c sum=n,ac837d7b87a8ca12f0343401d66d081d source=tfeed to_clusters=localhost from_cluster=localhost mtime=20221215145430.67089267 atime=20221215145430.658892516 mode=0664 parts=1,5,1,0,0 toto=pig
         #print( f'sum: {line[8]}')
         sum_algo=line[8][4]
         if sum_algo in post_count:
            post_count[ sum_algo ] += 1
         else: 
            post_count[ sum_algo ] = 1

   print( f"posts: {post_count}" )

   expected_post_count = { 's' : ( 0, 'sha512 sum posts' ), 'L' : ( 2, 'symoblic links'), 'n': ( 10, 'none' ) , 'R': ( 6, 'file removals' ) }


   bad=0
   good=0
   for e in expected_post_count:
      epi = expected_post_count[e]
 
      if e in post_count:
          actual = post_count[e]
      else:
          actual = 0

      if actual != expected_post_count[e][0]:
          bad+=1
          print( f'ERROR, for {expected_post_count[e][1]} expected: {expected_post_count[e][0]}, got {actual}' )
      else:
          good+=1
          print( f'GOOD, got {actual} for {expected_post_count[e][1]} as expected' )

   print( f"summary: good: {good}, bad {bad}, total {good+bad}" )
   sys.exit(bad)
