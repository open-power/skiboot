.. _skiboot-5.10.7:

==============
skiboot-5.10.7
==============

skiboot 5.10.7 was released on Friday March 21st, 2019. It replaces
:ref:`skiboot-5.10.6` as the current stable release in the 5.10.x series.

It is expected that this will be the final 5.10.x version, with 6.2.x taking
over as the main stable branch.

Over :ref:`skiboot-5.10.6`, we have the following fixes:

- libffs: Fix string truncation gcc warning.

  Use memcpy as other libffs functions do.

- hdata/i2c.c: fix building with gcc8

  hdata/test/../i2c.c:200:1: error: alignment 1 of ‘struct host_i2c_hdr’ is less than 4 [-Werror=packed-not-aligned]
     } __packed;
     ^

- opal-prd: Fix opal-prd crash

  Presently callback function from HBRT uses r11 to point to target function
  pointer. r12 is garbage. This works fine when we compile with "-no-pie" option
  (as we don't use r12 to calculate TOC).

  As per ABIv2 : "r12 : Function entry address at global entry point"

  With "-pie" compilation option, we have to set r12 to point to global function
  entry point. So that we can calculate TOC properly.

  Crash log without this patch:
    opal-prd[2864]: unhandled signal 11 at 0000000000029320 nip 00000 00102012830 lr 0000000102016890 code 1
