#!/bin/bash

set -euo pipefail

./tainted_unused_arg && exit 0

exit 1
