#!/bin/bash

set -uo pipefail
set -e
set -vx

if [ $(arch) == "x86_64" ]; then
    export CROSS=/opt/cross/gcc-8.4.0-nolibc/powerpc64-linux/bin/powerpc64-linux-
fi
if [ $(arch) == "ppc64le" ]; then
    export CROSS=/opt/cross/gcc-8.4.0-nolibc/powerpc64-linux/bin/powerpc64-linux-
fi

MAKE_J=$(nproc)

make -j${MAKE_J} all
make -j${MAKE_J} check
(make clean; cd external/gard && CROSS= make -j${MAKE_J})
(cd external/pflash; make -j${MAKE_J})
make clean
SKIBOOT_GCOV=1 make -j${MAKE_J}
SKIBOOT_GCOV=1 make -j${MAKE_J} check

make clean
rm -rf builddir
mkdir builddir
make SRC=$(pwd) -f ../Makefile -C builddir -j${MAKE_J}
make clean
