#!/bin/bash

set -euo pipefail

./tainted_rdi_untainted_di && exit 1

exit 0
