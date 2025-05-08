#!/bin/bash

set -euo pipefail

./tainted_ymm0 && exit 1

exit 0
