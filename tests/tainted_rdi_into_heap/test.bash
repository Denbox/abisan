#!/bin/bash

set -euo pipefail

./tainted_rdi_into_heap && exit 1

exit 0
