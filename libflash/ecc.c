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

#include <stdint.h>
#include <ecc.h>

/*
 * Matrix used for ECC calculation.
 *
 *  Each row of this is the set of data word bits that are used for
 *  the calculation of the corresponding ECC bit.  The parity of the
 *  bitset is the value of the ECC bit.
 *
 *  ie. ECC[n] = eccMatrix[n] & data
 *
 *  Note: To make the math easier (and less shifts in resulting code),
 *        row0 = ECC7.  HW numbering is MSB, order here is LSB.
 *
 *  These values come from the HW design of the ECC algorithm.
 */
static uint64_t eccmatrix[] = {
        0x0000e8423c0f99ff,
        0x00e8423c0f99ff00,
        0xe8423c0f99ff0000,
        0x423c0f99ff0000e8,
        0x3c0f99ff0000e842,
        0x0f99ff0000e8423c,
        0x99ff0000e8423c0f,
        0xff0000e8423c0f99
};

/**
 * Syndrome calculation matrix.
 *
 *  Maps syndrome to flipped bit.
 *
 *  To perform ECC correction, this matrix is a look-up of the bit
 *  that is bad based on the binary difference of the good and bad
 *  ECC.  This difference is called the "syndrome".
 *
 *  When a particular bit is on in the data, it cause a column from
 *  eccMatrix being XOR'd into the ECC field.  This column is the
 *  "effect" of each bit.  If a bit is flipped in the data then its
 *  "effect" is missing from the ECC.  You can calculate ECC on unknown
 *  quality data and compare the ECC field between the calculated
 *  value and the stored value.  If the difference is zero, then the
 *  data is clean.  If the difference is non-zero, you look up the
 *  difference in the syndrome table to identify the "effect" that
 *  is missing, which is the bit that is flipped.
 *
 *  Notice that ECC bit flips are recorded by a single "effect"
 *  bit (ie. 0x1, 0x2, 0x4, 0x8 ...) and double bit flips are identified
 *  by the UE status in the table.
 *
 *  Bits are in MSB order.
 */
static uint8_t syndromematrix[] = {
        GD, E7, E6, UE, E5, UE, UE, 47, E4, UE, UE, 37, UE, 35, 39, UE,
        E3, UE, UE, 48, UE, 30, 29, UE, UE, 57, 27, UE, 31, UE, UE, UE,
        E2, UE, UE, 17, UE, 18, 40, UE, UE, 58, 22, UE, 21, UE, UE, UE,
        UE, 16, 49, UE, 19, UE, UE, UE, 23, UE, UE, UE, UE, 20, UE, UE,
        E1, UE, UE, 51, UE, 46,  9, UE, UE, 34, 10, UE, 32, UE, UE, 36,
        UE, 62, 50, UE, 14, UE, UE, UE, 13, UE, UE, UE, UE, UE, UE, UE,
        UE, 61,  8, UE, 41, UE, UE, UE, 11, UE, UE, UE, UE, UE, UE, UE,
        15, UE, UE, UE, UE, UE, UE, UE, UE, UE, 12, UE, UE, UE, UE, UE,
        E0, UE, UE, 55, UE, 45, 43, UE, UE, 56, 38, UE,  1, UE, UE, UE,
        UE, 25, 26, UE,  2, UE, UE, UE, 24, UE, UE, UE, UE, UE, 28, UE,
        UE, 59, 54, UE, 42, UE, UE, 44,  6, UE, UE, UE, UE, UE, UE, UE,
         5, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE,
        UE, 63, 53, UE,  0, UE, UE, UE, 33, UE, UE, UE, UE, UE, UE, UE,
         3, UE, UE, 52, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE,
         7, UE, UE, UE, UE, UE, UE, UE, UE, 60, UE, UE, UE, UE, UE, UE,
        UE, UE, UE, UE,  4, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE,
};

/**
 * Create the ECC field corresponding to a 8-byte data field
 *
 *  @data:	The 8 byte data to generate ECC for.
 *  @return:	The 1 byte ECC corresponding to the data.
 */
static uint8_t eccgenerate(uint64_t data)
{
	int i;
        uint8_t result = 0;

        for (i = 0; i < 8; i++)
		result |= __builtin_parityl(eccmatrix[i] & data) << i;

        return result;
}

/**
 * Verify the data and ECC match or indicate how they are wrong.
 *
 * @data:	The data to check ECC on.
 * @ecc:	The [supposed] ECC for the data.
 *
 * @return:	eccBitfield or 0-64.
 *
 * @retval GD - Indicates the data is good (matches ECC).
 * @retval UE - Indicates the data is uncorrectable.
 * @retval all others - Indication of which bit is incorrect.
 */
static uint8_t eccverify(uint64_t data, uint8_t ecc)
{
        return syndromematrix[eccgenerate(data) ^ ecc];
}

/**
 * Copy data from an input buffer with ECC to an output buffer without ECC.
 * Correct it along the way and check for errors.
 *
 * @dst:	destination buffer without ECC
 * @src:	source buffer with ECC
 * @len:	number of bytes of data to copy (without ecc).
                     Must be 8 byte aligned.
 *
 * @return:	eccBitfield or 0-64.
 *
 * @retval GD - Data is good.
 * @retval UE - Data is uncorrectable.
 * @retval all others - which bit was corrected.
 */
uint8_t eccmemcpy(uint64_t *dst, uint64_t *src, uint32_t len)
{
	uint64_t *data;
	uint8_t *ecc;
	uint32_t i;
	uint8_t badbit;

	if (len & 0x7) {
		/* TODO: we could probably handle this */
		prerror("ECC data length must be 8 byte aligned length:%i\n",
			len);
		return UE;
	}

	/* Handle in chunks of 8 bytes, so adjust the length */
	len >>= 3;

	for (i = 0; i < len; i++) {
		data = (uint64_t *)((uint8_t *)src + i*9);
		ecc = (uint8_t *)data + 8;

		badbit = eccverify(*data, *ecc);
		if (badbit == UE) {
			prerror("ECC: uncorrectable error: %016lx %02x\n",
				(long unsigned int)*data, *ecc);
			return badbit;
		}
		*dst = *data;
		if (badbit <= UE)
			prlog(PR_INFO, "ECC: correctable error: %i\n", badbit);
		if (badbit < 64)
			*dst = *data ^ (1ul << (63 - badbit));
		dst++;
        }
        return GD;
}
