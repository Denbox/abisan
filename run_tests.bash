#!/bin/bash

set -euo pipefail

# The error code associated with a successful test
# ie. a test that is supposed to fail exits 1, otherwise 0
declare -A expected_results=(
	[tests/control]=0
	[tests/acccess_below_red_zone]=1
	[tests/clobber_r12]=1
	[tests/clobber_r13]=1
	[tests/clobber_r14]=1
	[tests/clobber_r15]=1
	[tests/clobber_rbp]=1
	[tests/clobber_rbx]=1
	[tests/clobber_rsp]=1
	[tests/tainted_rbp]=1
	[tests/tainted_rdi]=1
	[tests/tainted_rdi]=1
	[tests/tainted_rdi_into_heap]=1
	[tests/tainted_unused_arg]=1
)

passed=True

for t in tests/*; do
    pushd $t

    make clean
    make

   	# check for expected exit value
	default to 1 if not in array
	expected_exit_val=${expected_results[$t]:-1}
	  
	./test.bash

	exit_val=$?

	if [ $exit_val -ne $expected_exit_val ]; then
			echo -e "\e[35mTest $t failed. Expected exit value $expected_exit_val but got $exit_val\e[0m"
			passed=False
	else
			echo -e "\e[32mTest $t passed. Expected exit value $expected_exit_val and got $exit_val\e[0m"
	fi

	popd
done

if [ $passed ]; then
	echo 'All tests passed'
else
	echo 'Did not pass all tests'
fi


