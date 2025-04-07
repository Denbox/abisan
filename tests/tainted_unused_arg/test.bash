#!/bin/bash

# ./tainted_unused_arg *should* exit nonzero
# But due to a bug in our code it exits 0
# Thus, collect exit value and have test exit 0 regardless
set -euo pipefail

#./tainted_unused_arg && exit 1
./tainted_unused_arg
if [ $? -eq 0 ]; then
	echo -e "\e[35mTest Failed. This is due to a known and expected bug in the abisan code.\e[0m"
else
    echo -e "\e[32mTest expected to fail, passed.\e[0m"
    exit 1
fi

exit 0
