#!/bin/bash

set -e

eval "${COMMON_SUBROUTINES}"

cd "$(dirname "$(realpath "${BASH_SOURCE:-${0}}")")"

/usr/local/bin/labgrid-client -p example-place lock
/usr/local/bin/pytest --lg-env remote.yaml -s -vv
/usr/local/bin/labgrid-client -p example-place unlock
