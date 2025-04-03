#!/bin/bash

set -euo pipefail

./tainted_unused_arg && exit 1

exit 0
