#!/bin/bash

# test-miscprint.pnor is constructed as follows:
# PRESERVED,0x00000300,0x00000100,P,/dev/zero
# READONLY,0x00000400,0x00000100,R,/dev/zero
# REPROVISION,0x00000500,0x00000100,F,/dev/zero
# BACKUP,0x00000600,0x00000100,B,/dev/zero

wd="libflash/test"
pflash="./external/pflash/pflash"

pnor="$wd/test-miscprint.pnor"

output1=$(${pflash} --detail=1 -F "$pnor" | grep "\[P\]")
output2=$(${pflash} --detail=2 -F "$pnor" | grep "\[R\]")
output3=$(${pflash} --detail=3 -F "$pnor" | grep "\[F\]")
output4=$(${pflash} --detail=4 -F "$pnor" | grep "\[B\]")

if [[ $output1 == "PRESERVED [P]" && $output2 == "READONLY [R]" &&
      $output3 == "REPROVISION [F]" && $output4 == "BACKUP [B]" ]]; then
    echo "Test passed!"
    exit 0;
else
    echo "Test failed!"
    exit 1; 
fi

