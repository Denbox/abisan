#!/bin/bash

set -euo pipefail

./tainted_dil && exit 1

exit 0
