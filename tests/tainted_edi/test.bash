#!/bin/bash

set -euo pipefail

./tainted_edi && exit 1

exit 0
