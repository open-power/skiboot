# SPDX-License-Identifier: Apache-2.0
# IBM_PROLOG_BEGIN_TAG
# This is an automatically generated prolog.
#
# $Source: src/usr/secureboot/base/rom_entry.S $
#
# OpenPOWER HostBoot Project
#
# COPYRIGHT International Business Machines Corp. 2013,2016
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
# IBM_PROLOG_END_TAG

#.include "kernel/ppcconsts.S"

# Updated hostboot location is src/securerom/rom_entry.S.
# This also has a fix for TOC save frame pointer.

#include <stack.h>

.section .text

.global __cvc_verify_v1
.global __cvc_sha512_v1

__cvc_verify_v1:
__cvc_sha512_v1:

call_rom_entry:
    mflr %r0
    std %r0, 16(%r1)
    stdu %r1, -128(%r1)
    std %r2, STACK_TOC_OFFSET(%r1)
    li %r2, 0
    mtctr %r3
    mr %r3, %r4
    mr %r4, %r5
    mr %r5, %r6
    mr %r6, %r7
    mr %r7, %r8
    bctrl
    ld %r2, STACK_TOC_OFFSET(%r1)
    addi %r1, %r1, 128
    ld %r0, 16(%r1)
    mtlr %r0
    blr

