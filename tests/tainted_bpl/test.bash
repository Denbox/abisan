#!/bin/bash

set -euo pipefail

./tainted_bpl && exit 1

exit 0
