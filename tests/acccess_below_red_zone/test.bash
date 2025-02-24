#!/bin/bash

set -euo pipefail

./access_below_red_zone && exit 1

exit 0
