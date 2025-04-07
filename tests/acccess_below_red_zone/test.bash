#!/bin/bash

set -euo pipefail

./access_below_red_zone && exit 0

exit 1
