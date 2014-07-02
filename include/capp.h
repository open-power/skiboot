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
struct capp_ucode_lid_hdr {
    uint64_t eyecatcher;		/* 'CAPPULID' in ASCII */
    uint64_t version;
    uint64_t data_size;		  	/* total size of all capp microcode data following header */
    u8 reserved[40];			/* zeroed, pads to 64 byte boundary */
};

struct capp_ucode_data_hdr
{
    uint64_t eyecatcher;  		/* 'CAPPUCOD' in ASCII */
    u8 version;
    u8 reg;
    u8 reserved[2];
    uint32_t num_data_chunks;		/* Number of 8-byte chunks of data that follow this header */
};

enum capp_reg {
    apc_master_cresp		= 0x1,
    apc_master_uop_table	= 0x2,
    snp_ttype			= 0x3,
    snp_uop_table		= 0x4,
    apt_master_capi_ctrl	= 0x5,
    snoop_capi_cnfg		= 0x6,
    canned_presp_map0		= 0x7,
    canned_presp_map1		= 0x8,
    canned_presp_map2		= 0x9,
    flush_sue_state_map		= 0xA,
    apc_master_powerbus_ctrl	= 0xB
};

#define CAPP_SNP_ARRAY_ADDR_REG			0x2013028
#define CAPP_APC_MASTER_ARRAY_ADDR_REG		0x201302A
#define CAPP_SNP_ARRAY_WRITE_REG		0x2013801
#define CAPP_APC_MASTER_ARRAY_WRITE_REG		0x2013802

#define APC_MASTER_PB_CTRL			0x2013018
#define APC_MASTER_CONFIG			0x2013019
#define TRANSPORT_CONTROL			0x201301C
#define CANNED_PRESP_MAP0			0x201301D
#define CANNED_PRESP_MAP1			0x201301E
#define CANNED_PRESP_MAP2			0x201301F
#define CAPP_ERR_STATUS_CTRL			0x201300E
#define FLUSH_SUE_STATE_MAP			0x201300F
#define CAPP_EPOCH_TIMER_CTRL			0x201302C
#define FLUSH_UOP_CONFIG1			0x2013803
#define FLUSH_UOP_CONFIG2			0x2013804
#define SNOOP_CAPI_CONFIG			0x201301A
