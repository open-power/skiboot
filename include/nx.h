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

#ifndef __NX_H
#define __NX_H

/*************************************/
/* Register addresses and bit fields */
/*************************************/

#define NX_P7_SAT(sat, offset)	XSCOM_SAT(0x1, sat, offset)
#define NX_P8_SAT(sat, offset)	XSCOM_SAT(0xc, sat, offset)

/* Random Number Generator */
#define NX_P7_RNG_BAR		NX_P7_SAT(0x2, 0x0c)
#define NX_P8_RNG_BAR		NX_P8_SAT(0x2, 0x0d)
#define   NX_P7_RNG_BAR_ADDR		PPC_BITMASK(18, 51)
#define   NX_P8_RNG_BAR_ADDR		PPC_BITMASK(14, 51)
#define   NX_RNG_BAR_SIZE		PPC_BITMASK(53, 55)
#define   NX_RNG_BAR_ENABLE		PPC_BIT(52)

#define NX_P7_RNG_CFG		NX_P7_SAT(0x2, 0x12)
#define NX_P8_RNG_CFG		NX_P8_SAT(0x2, 0x12)
#define   NX_RNG_CFG_ENABLE		PPC_BIT(63)

/* Symmetric Crypto */
#define NX_P7_SYM_CFG		NX_P7_SAT(0x2, 0x09)
#define NX_P8_SYM_CFG		NX_P8_SAT(0x2, 0x0a)
#define   NX_SYM_CFG_CI			PPC_BITMASK(2, 14)
#define   NX_SYM_CFG_CT			PPC_BITMASK(18, 23)
#define   NX_SYM_CFG_FC_ENABLE		PPC_BITMASK(32, 39)
#define   NX_SYM_CFG_ENABLE		PPC_BIT(63)

/* Asymmetric Crypto */
#define NX_P7_ASYM_CFG		NX_P7_SAT(0x2, 0x0a)
#define NX_P8_ASYM_CFG		NX_P8_SAT(0x2, 0x0b)
#define   NX_ASYM_CFG_CI		PPC_BITMASK(2, 14)
#define   NX_ASYM_CFG_CT		PPC_BITMASK(18, 23)
#define   NX_ASYM_CFG_FC_ENABLE		PPC_BITMASK(32, 52)
#define   NX_ASYM_CFG_ENABLE		PPC_BIT(63)

/* 842 Compression */
#define NX_P7_842_CFG		NX_P7_SAT(0x2, 0x0b)
#define NX_P8_842_CFG		NX_P8_SAT(0x2, 0x0c)
#define   NX_842_CFG_CI			PPC_BITMASK(2, 14)
#define   NX_842_CFG_CT			PPC_BITMASK(18, 23)
#define   NX_842_CFG_FC_ENABLE		PPC_BITMASK(32, 36)
#define   NX_842_CFG_ENABLE		PPC_BIT(63)

/* DMA */
#define NX_P7_DMA_CFG		NX_P7_SAT(0x1, 0x02)
#define NX_P8_DMA_CFG		NX_P8_SAT(0x1, 0x02)
#define   NX_P8_DMA_CFG_842_COMPRESS_PREFETCH	PPC_BIT(23)
#define   NX_P8_DMA_CFG_842_DECOMPRESS_PREFETCH	PPC_BIT(24)
#define   NX_DMA_CFG_AES_SHA_MAX_RR		PPC_BITMASK(25, 28)
#define   NX_DMA_CFG_AMF_MAX_RR			PPC_BITMASK(29, 32)
#define   NX_DMA_CFG_842_COMPRESS_MAX_RR	PPC_BITMASK(33, 36)
#define   NX_DMA_CFG_842_DECOMPRESS_MAX_RR	PPC_BITMASK(37, 40)
#define   NX_DMA_CFG_AES_SHA_CSB_WR		PPC_BITMASK(41, 42)
#define   NX_DMA_CFG_AES_SHA_COMPLETION_MODE	PPC_BITMASK(43, 44)
#define   NX_DMA_CFG_AES_SHA_CPB_WR		PPC_BITMASK(45, 46)
#define   NX_DMA_CFG_AES_SHA_OUTPUT_DATA_WR	PPC_BIT(47)
#define   NX_DMA_CFG_AMF_CSB_WR			PPC_BITMASK(49, 50)
#define   NX_DMA_CFG_AMF_COMPLETION_MODE	PPC_BITMASK(51, 52)
#define   NX_DMA_CFG_AMF_CPB_WR			PPC_BITMASK(53, 54)
#define   NX_DMA_CFG_AMF_OUTPUT_DATA_WR		PPC_BIT(55)
#define   NX_DMA_CFG_842_SPBC			PPC_BIT(56)
#define   NX_DMA_CFG_842_CSB_WR			PPC_BITMASK(57, 58)
#define   NX_DMA_CFG_842_COMPLETION_MODE	PPC_BITMASK(59, 60)
#define   NX_DMA_CFG_842_CPB_WR			PPC_BITMASK(61, 62)
#define   NX_DMA_CFG_842_OUTPUT_DATA_WR		PPC_BIT(63)

/* Engine Enable Register */
#define NX_P7_EE_CFG		NX_P7_SAT(0x1, 0x01)
#define NX_P8_EE_CFG		NX_P8_SAT(0x1, 0x01)
#define   NX_EE_CFG_EFUSE		PPC_BIT(0)
#define   NX_EE_CFG_CH7			PPC_BIT(53) /* AMF */
#define   NX_EE_CFG_CH6			PPC_BIT(54) /* AMF */
#define   NX_EE_CFG_CH5			PPC_BIT(55) /* AMF */
#define   NX_EE_CFG_CH4			PPC_BIT(56) /* P7: SYM, P8: AMF */
#define   NX_EE_CFG_CH3			PPC_BIT(57) /* SYM */
#define   NX_EE_CFG_CH2			PPC_BIT(58) /* SYM */
#define   NX_EE_CFG_CH1			PPC_BIT(62) /* 842 */
#define   NX_EE_CFG_CH0			PPC_BIT(63) /* 842 */


/**************************************/
/* Register field values/restrictions */
/**************************************/

/* Arbitrary Coprocessor Type values */
#define NX_CT_SYM	(1)
#define NX_CT_ASYM	(2)
#define NX_CT_842	(3)

/* Coprocessor Instance counter
 * NX workbook, section 5.5.1
 * "Assigning <CT,CI> Values"
 */
#define NX_SYM_CFG_CI_MAX	(511)
#define NX_SYM_CFG_CI_LSHIFT	(2)
#define NX_ASYM_CFG_CI_MAX	(127)
#define NX_ASYM_CFG_CI_LSHIFT	(4)
#define NX_842_CFG_CI_MAX	(511)
#define NX_842_CFG_CI_LSHIFT	(2)

/* DMA configuration values
 * NX workbook, section 5.2.3, table 5-4
 * "DMA Configuration Register Bits"
 *
 * These values can be used for the AES/SHA, AMF, and 842 DMA
 * configuration fields in the DMA configuration register.
 *
 * Abbreviations used below:
 *   pDMA - "partial DMA write"
 *   fDMA - "full DMA write"
 *   CI - Cache Inject
 */
/* NX_DMA_CSB_WR values:
 * 0 = Always perform 8 or 16 byte pDMA
 * 1 = Do 128 byte CI if CSB at end of cache line, else pDMA
 * 2 = Do 128 byte fDMA if CSB at end of cache line, else pDMA
 */
#define NX_DMA_CSB_WR_PDMA		(0)
#define NX_DMA_CSB_WR_CI		(1)
#define NX_DMA_CSB_WR_FDMA		(2)
/* NX_DMA_COMPLETION_MODE values:
 * 0 = Always perform 8 byte pDMA
 * 1 = Do 128 byte CI, replicating 8 bytes across entire 128 byte cache line
 * 2 = Do 128 byte fDMA, replicating 8 bytes across entire 128 byte cache line
 */
#define NX_DMA_COMPLETION_MODE_PDMA	(0)
#define NX_DMA_COMPLETION_MODE_CI	(1)
#define NX_DMA_COMPLETION_MODE_FDMA	(2)
/* NX_DMA_CPB_WR values:
 * 0 = Always do pDMA or fDMA, based on number of bytes and alignment
 * 1 = Always do pDMA on non-aligned cache lines, fDMA on aligned cache lines
 *      (may store dummy data at the end of the aligned data)
 * 2 = Do 128 byte CI when writing 128 aligned bytes, else pDMA
 * 3 = Do 128 byte CI when writing aligned cache lines, else pDMA
 *      (may store dummy data at the end of the aligned data)
 */
#define NX_DMA_CPB_WR_DMA_NOPAD		(0)
#define NX_DMA_CPB_WR_DMA_PAD		(1)
#define NX_DMA_CPB_WR_CI_NOPAD		(2)
#define NX_DMA_CPB_WR_CI_PAD		(3)
/* NX_DMA_OUTPUT_DATA_WR values:
 * 0 = Always do pDMA or fDMA, based on number of bytes and alignment
 * 1 = Do 128 byte CI when writing 128 aligned bytes, else pDMA
 */
#define NX_DMA_OUTPUT_DATA_WR_DMA	(0)
#define NX_DMA_OUTPUT_DATA_WR_CI	(1)


/******************************/
/* NX node creation functions */
/******************************/

extern void nx_create_rng_node(struct dt_node *);
extern void nx_create_crypto_node(struct dt_node *);
extern void nx_create_842_node(struct dt_node *);

extern void nx_init(void);

#endif /* __NX_H */
