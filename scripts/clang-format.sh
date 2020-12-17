#!/bin/bash

set -e
set -u

cd "$( dirname "$0" )/.."

find src/ include/ tests/mock/ tests/integration/ -iname '*.hpp' -o -iname '*.h' -o -iname '*.cpp' | xargs clang-format -i
