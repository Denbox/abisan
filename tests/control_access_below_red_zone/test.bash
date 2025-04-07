0;10;1c#!/bin/bash

set -o pipefail



val=$(echo $ABISAN_TUNABLES | cut --delimiter ";" --fields 1)

./control_access_below_red_zone

ret=$?
# If red zone is enabled, test should not generate warnings or errors
# Otherwise, test should generate warnings or errors
if [[ "$val" == *"1"* ]]; then
    exit $ret
else
    echo -e "\e[35mRed Zone is disabled, so control_access_below_red_zone test is expected to fail because it touches below the stack.\e[0m"
    if [ $ret -eq 0 ]; then
        exit 1
    fi
fi


exit 0
