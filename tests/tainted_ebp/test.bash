#!/bin/bash

set -euo pipefail

./tainted_ebp && exit 1

exit 0
