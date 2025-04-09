#!/bin/bash

set -euo pipefail

./tainted_di && exit 1

exit 0
