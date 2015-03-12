/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* This is based on the hostboot ecc code */

#ifndef __ECC_H
#define __ECC_H

#include <stdint.h>
#include <ccan/endian/endian.h>

/* Bit field identifiers for syndrome calculations. */
enum eccbitfields
{
        GD = 0xff,      //< Good, ECC matches.
        UE = 0xfe,      //< Uncorrectable.
        E0 = 71,        //< Error in ECC bit 0
        E1 = 70,        //< Error in ECC bit 1
        E2 = 69,        //< Error in ECC bit 2
        E3 = 68,        //< Error in ECC bit 3
        E4 = 67,        //< Error in ECC bit 4
        E5 = 66,        //< Error in ECC bit 5
        E6 = 65,        //< Error in ECC bit 6
        E7 = 64         //< Error in ECC bit 7
};

struct ecc64 {
	beint64_t data;
	uint8_t ecc;
} __attribute__((__packed__));

extern uint8_t memcpy_from_ecc(uint64_t *dst, struct ecc64 *src, uint32_t len);

extern uint8_t memcpy_to_ecc(struct ecc64 *dst, const uint64_t *src, uint32_t len);

/*
 * Calculate the size of a buffer if ECC is added
 *
 * We add 1 byte of ecc for every 8 bytes of data.  So we need to round up to 8
 * bytes length and then add 1/8
 */
#ifndef ALIGN_UP
#define ALIGN_UP(_v, _a)	(((_v) + (_a) - 1) & ~((_a) - 1))
#endif

#define ECC_SIZE(len) (ALIGN_UP((len), 8) >> 3)
#define ECC_BUFFER_SIZE(len) (ALIGN_UP((len), 8) + ECC_SIZE(len))
#define ECC_BUFFER_SIZE_CHECK(len) ((len) % 9)
#define BUFFER_SIZE_MINUS_ECC(len) ((len) * 8 / 9)

#endif
