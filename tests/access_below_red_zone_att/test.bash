#!/bin/bash

set -euo pipefail

./access_below_red_zone_att && exit 1

exit 0
