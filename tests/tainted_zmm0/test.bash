#!/bin/bash

set -euo pipefail

./tainted_zmm0 && exit 1

exit 0
