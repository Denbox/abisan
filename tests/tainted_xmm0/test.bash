#!/bin/bash

set -euo pipefail

./tainted_xmm0 && exit 1

exit 0
