#!/bin/bash

set -euo pipefail

./tainted_rdi_into_heap && exit 0

exit 1
