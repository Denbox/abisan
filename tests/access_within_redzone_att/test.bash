#!/bin/bash

set -euo pipefail

./access_within_red_zone && exit 1

exit 0
