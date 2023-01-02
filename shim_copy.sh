

# job step 0 - setup...
if [ ! -d ~/test ]; then
     mkdir ~/test
fi

echo "ignore rm errors.. cleaning before start"
rm -rf shim_dirA/

for d in shim_dirA shim_dirB; do
        if [ -d $d ]; then
            echo "ignore rm -rf $d"
            rm -rf $d
        fi
        mkdir $d
done 
mkdir -p ~/.config/sr3/subscribe
mkdir -p ~/.config/sr3/cpost
cp local_copy.conf ~/.config/sr3/subscribe
cp local_post.conf ~/.config/sr3/cpost
sr3 declare cpost/local_post
sr3 declare subscribe/local_copy
sr3 start subscribe/local_copy.conf

export SR_POST_CONFIG=`pwd`/local_post.conf
export LD_PRELOAD=`pwd`/libsr3shim.so.1.0.0
export LD_LIBRARY_PATH=`pwd`:${LD_LIBRARY_PATH}
export SR_SHIMDEBUG=99
cd shim_dirA
../shimcopy1.sh &
unset SR_POST_CONFIG
unset SR_SHIMDEBUG
unset LD_PRELOAD
wait


# job step 2... copy.
cd  ..
echo "waiting a few seconds for copies to complete"
sleep 10
sr3 remove cpost/local_post.conf
sr3 stop subscribe/local_copy.conf
sr3 remove subscribe/local_copy.conf

echo "#test 0 comment comparing trees"
    
    
cd shim_dirA
find -H . -type f | xargs md5sum >../dirA.sums
cd ../shim_dirB
find -H . -type f | xargs md5sum >../dirB.sums
cd ..
    
if diff dirA.sums dirB.sums; then
       echo "RESULT: Good! trees the same"
else
       echo "RESULT: BAD trees different"
fi
