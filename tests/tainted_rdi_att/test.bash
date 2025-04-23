#!/bin/bash

set -euo pipefail

./tainted_rdi_att && exit 1

exit 0
