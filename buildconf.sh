#!/bin/bash

set -x
set -e

autoreconf -fvi
rm -rf autom4te*.cache

exit 0
