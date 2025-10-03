#!/bin/bash

cd shim_dirA
find -H . -type f | xargs -d '\n' md5sum >../dirA.sums
cd ../shim_dirB
find -H . -type f | xargs -d '\n' md5sum >../dirB.sums
cd ..

# this only captures file differences
diffs="`diff dirA.sums dirB.sums| wc -l`"

# need to check for directories too
dir_diffs="$(diff -q --no-dereference -r shim_dirA shim_dirB)"
dir_diffs_result=$?

if [ "${diffs}" -eq 0 ] && [ "${dir_diffs_result}" -eq 0 ]; then
       echo "RESULT: Good! trees the same"
else
        if [ "${dir_diffs_result}" -ne 0 ]; then
                dir_diffs_msg="and these other differences: ${dir_diffs/$'\n'/, }"
        fi
       echo "RESULT: BAD trees have $diffs file differences ${dir_diffs_msg}"
fi
