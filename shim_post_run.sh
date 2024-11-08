set -x

#which bash

echo "#test 0 comment 000 shim test posting start"

echo "#test 1 sha512 070 cp command"
cp libsr3shim.c ~/test/hoho_my_darling.txt


echo "#test 1 sha512 070 cp command"
valgrind  --show-reachable=yes --track-origins=yes --leak-check=full cp libsr3shim.c ~/test/hoho_my_darling.txt
