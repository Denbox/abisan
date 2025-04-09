#!/bin/bash

set -euo pipefail

./tainted_rdi_untainted_edi && exit 1

exit 0
