#!/bin/bash

set -euo pipefail

./tainted_bh && exit 1

exit 0
