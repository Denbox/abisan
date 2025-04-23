#!/bin/bash

set -euo pipefail

start_syntax="${ABISAN_TUNABLES_SYNTAX:-}"

export ABISAN_TUNABLES_SYNTAX="intel"
for t in tests/*; do
    if [[ "$t" == *"att"* ]]; then
        export ABISAN_TUNABLES_SYNTAX="att"
    elif [[ "$ABISAN_TUNABLES_SYNTAX" == "att" ]]; then
         export ABISAN_TUNABLES_SYNTAX="intel"
    fi
	pushd $t
	make clean
   	make
	./test.bash
	popd
done

if [[ "$start_syntax" == "" ]]; then
    unset ABISAN_TUNABLES_SYNTAX
else
    export ABISAN_TUNABLES_SYNTAX=$start_syntax
fi
echo -e "\e[32mAll tests ran as expected\e[0m"
