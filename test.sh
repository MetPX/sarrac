export SR_POST_CONFIG=`pwd`/test_post.conf
export LD_PRELOAD=`pwd`/libsrshim.so.1.0.0

#echo "ldd /usr/bin/python"
#ldd /usr/bin/python2.7

#export LD_DEBUG=bindings

#export SRSHIMDEBUG=lala
#export SRSHIMMV=po
set -x
echo "hoho" >>~/test/hoho

/usr/bin/python2.7 pyiotest
cp libsrshim.c ~/test/hoho_my_darling.txt
touch hihi
ln -s hoho haha
mv haha hihi
ln hihi hoohoo
mv ~/test/hoho_my_darling.txt ~/test/hoho2.log
rm hihi

rm ~/test/hoho2.log
mkdir dirone
echo "fileone" >>dirone/fileone
mkdir dirone/dirtwo
echo "filetwo" >>dirone/dirtwo/filetwo
mv dirone dirthree
rm -rf dirthree
