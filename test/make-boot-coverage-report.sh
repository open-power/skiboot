#!/bin/bash

# We cheat and do this in a shell script so I don't go Makefile crazy.

SKIBOOT_GCOV_ADDR=`perl -e "printf '0x%x', 0x30000000 + 0x\`grep gcov_info_list skiboot.map|cut -f 1 -d ' '\`"`

find .|grep '\.gcda$'|xargs rm -f

./extract-gcov ./external/mambo/skiboot-hello_world.dump $SKIBOOT_GCOV_ADDR
lcov -q -b . -d . -c -o skiboot-hello_world.info --gcov-tool ${CROSS}gcov
find .|grep '\.gcda$'|xargs rm -f

./extract-gcov ./external/mambo/skiboot-boot_test.dump $SKIBOOT_GCOV_ADDR
lcov -q -b . -d . -c -o skiboot-boot_test.info --gcov-tool ${CROSS}gcov
find .|grep '\.gcda$'|xargs rm -f

lcov -q -b . -d . --gcov-tool ${CROSS}gcov -o skiboot-boot.info -a skiboot-boot_test.info -a skiboot-hello_world.info

genhtml -o boot-coverage-report skiboot-boot.info