#!/bin/bash

set -euo pipefail

for t in tests/*; do
	pushd $t
	make clean
   	make
	./test.bash
	popd
done

echo -e "\e[32mAll tests ran as expected\e[0m"
echo -e "\e[32mToDo: test access below red zone with small stack\e[0m"


