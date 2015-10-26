#!/bin/bash


if [ -z "$MAMBO_PATH" ]; then
    MAMBO_PATH=/opt/ibm/systemsim-p8/
fi

if [ -z "$MAMBO_BINARY" ]; then
    MAMBO_BINARY="/run/pegasus/power8"
fi

if [ ! -x "$MAMBO_PATH/$MAMBO_BINARY" ]; then
    echo 'Could not find executable MAMBO_BINARY. Skipping hello_world test';
    exit 0;
fi

if [ -n "$KERNEL" ]; then
    echo 'Please rebuild skiboot without KERNEL set. Skipping hello_world test';
    exit 0;
fi

if [ ! `command -v expect` ]; then
    echo 'Could not find expect binary. Skipping hello_world test';
    exit 0;
fi

if [ -z "$SKIBOOT_ZIMAGE" ]; then
    export SKIBOOT_ZIMAGE=`pwd`/zImage.epapr
fi

if [ ! -f "$SKIBOOT_ZIMAGE" ]; then
    echo "No $SKIBOOT_ZIMAGE, skipping boot test";
    exit 0;
fi

if [ -z "$SKIBOOT_MEM_DUMP" ]; then
    export SKIBOOT_MEM_DUMP=skiboot-boot_test.dump
fi

# Currently getting some core dumps from mambo, so disable them!
OLD_ULIMIT_C=`ulimit -c`
ulimit -c 0

( cd external/mambo;
cat <<EOF | expect
set timeout 600
spawn $MAMBO_PATH/$MAMBO_BINARY -n -f ../../test/run_boot_test.tcl
expect {
timeout { send_user "\nTimeout waiting for petitboot\n"; exit 1 }
eof { send_user "\nUnexpected EOF\n;" exit 1 }
"Execution stopped: Sim Support exit requested stop"
}
wait
exit 0
EOF
)
ulimit -c $OLD_ULIMIT_C
echo
exit 0;
