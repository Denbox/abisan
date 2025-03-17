#!/bin/bash

set -euo pipefail

./tainted_rbp && exit 1

exit 0
