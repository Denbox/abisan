#!/bin/bash

set -euo pipefail

./tainted_rbp && exit 0

exit 1
