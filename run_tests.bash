#!/bin/bash

set -euo pipefail

for t in tests/*; do
	pushd $t
	make clean
   	make
	./test.bash
	popd
done

echo -e "\e[32mAll tests passed\e[0m"



