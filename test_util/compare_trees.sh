#!/bin/bash

check_links=false
if [[ " $* " == *"--check-links"* ]]; then
    check_links=true
fi


# check for file differences
cd shim_dirA
find -H . -type f | xargs -d '\n' md5sum >../dirA.sums
cd ../shim_dirB
find -H . -type f | xargs -d '\n' md5sum >../dirB.sums
cd ..

diffs="`diff dirA.sums dirB.sums| wc -l`"


# check for link differences
if [[ $check_links == true ]]; then
	cd shim_dirA
	find . -type l  | xargs ls -al | cut --bytes=42- >../dirA.links
	cd ../shim_dirB
	find . -type l  | xargs ls -al | cut --bytes=42- >../dirB.links
	cd ..
	sed 's+shim_dirB+shim_dirA+' dirB.links >dirC.links

	linkdiffs="`diff dirA.links dirC.links|wc -l`"
fi


# check for directory differences (missing dirs, extra dirs, etc.)
dir_diffs="$(diff -q --no-dereference -r shim_dirA shim_dirB)"
dir_diffs_result=$?
if [ "${dir_diffs_result}" -ne 0 ]; then
	dir_diffs_msg="and these other differences: ${dir_diffs/$'\n'/, }"
fi


# report result with links
if [[ $check_links == true ]]; then

	if [ "${diffs}" -eq 0 ] && [ "${dir_diffs_result}" -eq 0 ] && [ "${linkdiffs}" -eq 0 ]; then
		echo "RESULT: Good! trees links the same: $(wc -l dirA.sums) files and $(wc -l dirA.links) links mirrored"
	else
		echo "RESULT: BAD tree differences in $diffs files, and $linkdiffs links ${dir_diffs_msg}"
	fi

# report result without links
else

	if [ "${diffs}" -eq 0 ] && [ "${dir_diffs_result}" -eq 0 ]; then
		echo "RESULT: Good! trees the same: $(wc -l dirA.sums) files mirrored"
	else
		echo "RESULT: BAD trees have $diffs file differences ${dir_diffs_msg}"
	fi
fi
