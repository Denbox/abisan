#!/bin/bash

set -euo pipefail

./tainted_rdi_untainted_dil && exit 1

exit 0
