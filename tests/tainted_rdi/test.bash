#!/bin/bash

set -euo pipefail

./tainted_rdi && exit 1

exit 0
