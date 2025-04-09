#!/bin/bash

set -euo pipefail

./tainted_bp && exit 1

exit 0
