#!/bin/bash

set -euo pipefail

./tainted_rdi && exit 0

exit 1
