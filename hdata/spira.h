// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __SPIRA_H
#define __SPIRA_H

#include "hdif.h"

/*
 * The SPIRA-H and SPIRA-S structures
 *
 * SPIRA-H is built in the primary hypervisor (skiboot) lid, pointed to by
 * the NACA and provides details to the boot firmware.
 *
 * SPIRA-S is built at IPL time by the boot firmware at the host data area
 * location specified in SPIRA-H, and thus must be parsed.
 */

struct spira_ntuple {
	__be64		addr;
	__be16		alloc_cnt;
	__be16		act_cnt;
	__be32		alloc_len;
	__be32		act_len;
	__be32		tce_off;
	__be64		padding;
} __packed;

/* SPIRA-H signature */
#define SPIRAH_HDIF_SIG		"SPIRAH"

/* First version of the secure boot compliant design. */
#define SPIRAH_VERSION		0x50

/* N-tuples in SPIRAH */
#define SPIRAH_NTUPLES_COUNT	0x6

struct spirah_ntuples {
	struct HDIF_array_hdr	array_hdr;	/* 0x030 */
	struct spira_ntuple	hs_data_area;	/* 0x040 */
	struct spira_ntuple	proc_init;	/* 0x060 */
	struct spira_ntuple	cpu_ctrl;	/* 0x080 */
	struct spira_ntuple	mdump_src;	/* 0x0a0 */
	struct spira_ntuple	mdump_dst;	/* 0x0c0 */
	struct spira_ntuple	mdump_res;	/* 0x0e0 */
	struct spira_ntuple	proc_dump_area;	/* 0x100 */
};

struct spirah {
	struct HDIF_common_hdr	hdr;
	struct HDIF_idata_ptr	ntuples_ptr;
	__be64			pad;
	struct spirah_ntuples	ntuples;
	u8			reserved[0xE0];
} __packed __align(0x100);

extern struct spirah spirah;

/* SPIRA-S signature */
#define SPIRAS_HDIF_SIG		"SPIRAS"

/* First version on 810 release */
#define SPIRAS_VERSION_P8	0x40
#define SPIRAS_VERSION_P9	0x50

/* N-tuples in SPIRAS */
#define SPIRAS_NTUPLES_COUNT	0x10

struct spiras_ntuples {
	struct HDIF_array_hdr	array_hdr;		/* 0x030 */
	struct spira_ntuple	sp_subsys;		/* 0x040 */
	struct spira_ntuple	ipl_parms;		/* 0x060 */
	struct spira_ntuple	nt_enclosure_vpd;	/* 0x080 */
	struct spira_ntuple	slca;			/* 0x0a0 */
	struct spira_ntuple	backplane_vpd;		/* 0x0c0 */
	struct spira_ntuple	system_vpd;		/* 0x0e0 */
	struct spira_ntuple	clock_vpd;		/* 0x100 */
	struct spira_ntuple	anchor_vpd;		/* 0x120 */
	struct spira_ntuple	op_panel_vpd;		/* 0x140 */
	struct spira_ntuple	misc_cec_fru_vpd;	/* 0x160 */
	struct spira_ntuple	ms_vpd;			/* 0x180 */
	struct spira_ntuple	cec_iohub_fru;		/* 0x1a0 */
	struct spira_ntuple	pcia;			/* 0x1c0 */
	struct spira_ntuple	proc_chip;		/* 0x1e0 */
	struct spira_ntuple	hs_data;		/* 0x200 */
	struct spira_ntuple	hbrt_data;		/* 0x220 */
	struct spira_ntuple	ipmi_sensor;		/* 0x240 */
	struct spira_ntuple	node_stb_data;		/* 0x260 */
};

struct spiras {
	struct HDIF_common_hdr	hdr;
	struct HDIF_idata_ptr	ntuples_ptr;
	__be64			pad;
	struct spiras_ntuples	ntuples;
	u8			reserved[0x180];
} __packed __align(0x100);

extern struct spiras *skiboot_constant_addr spiras;

/* This macro can be used to check the validity of a pointer returned
 * by one of the HDIF API functions. It returns true if the pointer
 * appears valid. If it's not valid and not NULL, it will print some
 * error in the log as well.
 */
#define CHECK_SPPTR(_ptr)	spira_check_ptr(_ptr, __FILE__, __LINE__)

#define get_hdif(ntuple, id) __get_hdif((ntuple), (id), __FILE__, __LINE__)

extern struct HDIF_common_hdr *__get_hdif(struct spira_ntuple *n,
					  const char id[],
					  const char *file, int line);

#define for_each_ntuple_idx(_ntuples, _p, _idx, _id)			\
	for (_p = get_hdif((_ntuples), _id ""), _idx = 0;		\
	     _p && _idx < be16_to_cpu((_ntuples)->act_cnt);		\
	     _p = (void *)_p + be32_to_cpu((_ntuples)->alloc_len), _idx++)

#define for_each_ntuple(_ntuples, _p, _id)				\
	for (_p = get_hdif((_ntuples), _id "");				\
	     _p && (void *)_p < ntuple_addr(_ntuples)			\
		     + (be16_to_cpu((_ntuples)->act_cnt) *		\
			be32_to_cpu((_ntuples)->alloc_len));		\
	     _p = (void *)_p + be32_to_cpu((_ntuples)->alloc_len))

#define for_each_pcia(s, p) for_each_ntuple(&(s)->ntuples.pcia, p, SPPCIA_HDIF_SIG)

/* We override these for testing. */
#ifndef ntuple_addr
#define ntuple_addr(_ntuples) ((void *)BE64_TO_CPU((_ntuples)->addr))
#endif

#ifndef spira_check_ptr
extern bool spira_check_ptr(const void *ptr, const char *file,
			    unsigned int line);
#endif

struct proc_init_data {
	struct HDIF_common_hdr	hdr;
	struct HDIF_idata_ptr	regs_ptr;
	struct {
		__be64	nia;
		__be64	msr;
		__be64	nia_charm_time;
		__be64	msr_charm_time;
	} regs;
} __packed __align(0x10);

/*
 * The FRU ID structure is used in several tuples, so we
 * define it generically here
 */
struct spira_fru_id {
	__be16		slca_index;
	__be16		rsrc_id;	/* formerly VPD port number */
} __packed;

/*
 * The FRU operational status structure is used in several
 * tuples, so we define it generically here
 */
struct spira_fru_op_status {
	uint8_t	flags;
#define FRU_OP_STATUS_FLAG_USED		0x02 /* If 0 -> not used (redundant) */
#define FRU_OP_STATUS_FLAG_FUNCTIONAL	0x01 /* If 0 -> non-functional */
	uint8_t	reserved[3];
} __packed;

/*
 * Move VPD related stuff to another file ...
 */
#define VPD_ID(_a, _b)	((_a) << 8 | (_b))

/*
 * Service Processor Subsystem Structure
 *
 * This structure contains several internal data blocks
 * describing the service processor(s) in the system
 */

#define SPSS_HDIF_SIG	"SPINFO"

/* Idata index 0 : FRU ID Data */
#define SPSS_IDATA_FRU_ID	0

/* Idata index 1 : Keyword VPD for the FSP instance */
#define SPSS_IDATA_KEYWORD_VPD	1

/* Idata index 2 : SP Implementation */
#define SPSS_IDATA_SP_IMPL	2

struct spss_sp_impl {
	__be16	hw_version;
	__be16	sw_version;
	__be16	func_flags;
#define SPSS_SP_IMPL_FLAGS_INSTALLED	0x8000
#define SPSS_SP_IMPL_FLAGS_FUNCTIONAL	0x4000
#define SPSS_SP_IMPL_FLAGS_PRIMARY	0x2000
	u8	chip_version;
	u8	reserved;
	u8	sp_family[64];
} __packed;

/* Idata index 3 is deprecated */

/* Idata index 4 : SP Memory Locator */
#define SPSS_IDATA_SP_MEMLOC	4

/* Idata index 5 : SP I/O path array */
#define SPSS_IDATA_SP_IOPATH	5

/* An HDIF array of IO path */
struct spss_iopath {
	__be16	iopath_type;
#define SPSS_IOPATH_TYPE_IOHUB_PHB	0x0001
#define SPSS_IOPATH_TYPE_PSI		0x0002
#define SPSS_IOPATH_TYPE_LPC		0x0003
	union {
		struct {
			__be16	iohub_chip_inst;
			__be16	iohub_chip_port;
			__be16	phb_id;
		} __packed iohub_phb;

		struct {
			__be16	link_status;
#define SPSS_IO_PATH_PSI_LINK_BAD_FRU	0x0000
#define SPSS_IO_PATH_PSI_LINK_CURRENT	0x0001
#define SPSS_IO_PATH_PSI_LINK_BACKUP	0x0002
			u8	ml2_version;
			u8	reserved;
			__be16	slca_count;
			u8	slca_idx[16];
			__be32	proc_chip_id;
			__be32	reserved2;
			__be64	gxhb_base;
		} __packed psi;

		struct { /* only populated after version 0x30 */
			__be16	link_status;
#define LPC_STATUS_STUFFED 0x0000
#define LPC_STATUS_ACTIVE  0x0001
			uint8_t ml2_version;
			uint8_t reserved[3];
			__be32	chip_id;

			__be32	io_bar;
			__be32	memory_bar;
			__be32	firmware_bar;
			__be32	internal_bar;

			__be32	mctp_base;

			__be64	uart_base;
			__be32	uart_size;
			__be32	uart_clk;  /* UART baud clock in Hz */
			__be32	uart_baud; /* UART baud rate */

			uint8_t uart_int_number;
			uint8_t uart_int_type;
#define			UART_INT_LVL_LOW	0x1
#define			UART_INT_RISING		0x2
#define			UART_INT_LVL_HIGH	0x3
			uint8_t uart_valid;
			uint8_t reserved3;

			__be64	bt_base;
			__be32	bt_size;
			uint8_t	bt_sms_int_num;
			uint8_t	bt_bmc_response_int_num;
			uint8_t	reserved4[2];

			__be16	kcs_data_reg_addr;
			__be16	kcs_status_reg_addr;
			uint8_t kcs_int_number;

			__be64	uart2_base;
			__be32	uart2_size;
			__be32	uart2_clk;  /* UART baud clock in Hz */
			__be32	uart2_baud; /* UART baud rate */
			uint8_t uart2_int_number;
			uint8_t uart2_int_type;
			uint8_t uart2_valid;
			uint8_t reserved5;
		} __packed lpc;
	};
} __packed;

/*
 * IPL Parms structure
 *
 */

/* Idata index 0: System Parameters */
#define IPLPARAMS_SYSPARAMS	0

struct iplparams_sysparams {
	char		sys_model[4];
	char		cpu_feature_code[4];
	__be32		effective_pvr;
	__be32		system_type;
	uint8_t		num_lpar_oct[8];
	__be32		abc_bus_speed;
	__be32		wxyz_bus_speed;
	__be32		sys_eco_mode;
#define SYS_ATTR_MULTIPLE_TPM PPC_BIT32(0)
#define SYS_ATTR_RISK_LEVEL PPC_BIT32(3)
#define SYS_ATTR_MPIPL_SUPPORTED PPC_BIT32(5)
	__be32		sys_attributes;
	__be32		mem_scrubbing;
	__be16		cur_spl_value;
	uint8_t		pump_mode;		/* Reserved */
	uint8_t		use_pore_sleep;
	__be32		pore_image_size;	/* Reserved */
	uint8_t		vtpm_enabled;
	uint8_t		hw_page_table_size;	/* >= 0x59 */
	__be16		hv_disp_wheel;		/* >= 0x58 */
	__be32		nest_freq_mhz;		/* >= 0x5b */
	uint8_t		split_core_mode;	/* >= 0x5c */
	uint8_t		reserved[1];
#define KEY_CLEAR_ALL     PPC_BIT16(0)
#define KEY_CLEAR_OS_KEYS PPC_BIT16(1)
#define KEY_CLEAR_MFG     PPC_BIT16(7)
	__be16          host_fw_key_clear;
	uint8_t		sys_vendor[64];		/* >= 0x5f */
#define SEC_CONTAINER_SIG_CHECKING PPC_BIT16(0)
#define SEC_HASHES_EXTENDED_TO_TPM PPC_BIT16(1)
#define PHYSICAL_PRESENCE_ASSERTED PPC_BIT16(3)
	__be16		sys_sec_setting;	/* >= 0x60 */
	__be16		tpm_config_bit;		/* >= 0x60 */
	__be16		tpm_drawer;		/* >= 0x60 */
	__be16		hw_key_hash_size;	/* >= 0x60 */
#define SYSPARAMS_HW_KEY_HASH_MAX   64
	uint8_t		hw_key_hash[SYSPARAMS_HW_KEY_HASH_MAX];  /* >= 0x60 */
	uint8_t		sys_family_str[64];	/* vendor,name */
	uint8_t		sys_type_str[64];	/* vendor,type */
} __packed;

/* Idata index 1: IPL parameters */
#define IPLPARAMS_IPLPARAMS	1

struct iplparams_iplparams {
	uint8_t		reserved;
	uint8_t		hv_ipl_dest;
	uint8_t		ipl_side;
#define IPLPARAMS_CEC_FW_IPL_SIDE_TEMP	0x10
#define IPLPARAMS_FSP_FW_IPL_SIDE_TEMP	0x01
	uint8_t		ipl_speed;
	__be16		cec_ipl_attrib;
#define IPLPARAMS_ATTRIB_MEM_PRESERVE	PPC_BIT16(2)
	uint8_t		cec_ipl_maj_type;
#define IPLPARAMS_MAJ_TYPE_REIPL	0x1
	uint8_t		cec_ipl_min_type;
#define IPLPARAMS_MIN_TYPE_POST_DUMP	0xc
#define IPLPARAMS_MIN_TYPE_PLAT_REBOOT	0xd
	uint8_t		os_ipl_mode;
	uint8_t		keylock_pos;
	uint8_t		lmb_size;
	uint8_t		deprecated;
	__be32		max_hsl_opticonnect;
	__be32		other_attrib;
#define IPLPARAMS_OATTR_RST_PCI_BUSNO	0x08000000
#define IPLPARAMS_OATTR_CLEAR_NVRAM	0x04000000
#define IPLPARAMS_OATRR_LIGHT_PATH	0x00000004
	__be16		huge_page_count;
	uint8_t		huge_page_size;
#define IPLPARAMS_HUGE_PG_SIZE_16G	0
	uint8_t		num_vlan_switches;
	__be32		reserved2;
	__be32		enlarge_io;	/* >= 0x5a */
	uint8_t		core_config;
#define IPLPARAMS_CORE_NORMAL	0x00
#define IPLPARAMS_CORE_FUSE	0x01
} __packed;

/* Idata index 4: Platform Dump Descriptor */
#define IPLPARAMS_PLATFORM_DUMP		4

struct iplparams_dump {
	__be16	flags;
	uint8_t	reserved1;
	uint8_t policy;
#define HYP_DUMP_POLICY_NORMAL	0x00
	__be32	dump_id;
	__be64	reserved2;
	__be64	act_dump_sz;
	__be32	max_hw_dump_sz;
	__be32	act_hw_dump_sz;
	__be32	max_sp_dump_sz;
	__be32	plid;
} __packed;

/* Idata index 8: serial ports */
#define IPLPARMS_IDATA_SERIAL	8

/* An HDIF array of serial descriptions */
struct iplparms_serial {
	uint8_t		loc_code[LOC_CODE_SIZE];
	__be16		rsrc_id;
	__be16		flags;
#define PLPARMS_SERIAL_FLAGS_CALLHOME	0x8000
} __packed;

/* Idata index 9: FW features */
#define IPLPARAMS_FEATURES	9
struct iplparams_feature {
	char name[64];
	__be64 flags;
} __packed;

/*
 * Chip TOD structure
 *
 * This is an array of 32 entries (I assume per possible chip)
 */

/* Idata index 0: Chip ID data (array) */
#define CHIPTOD_IDATA_CHIPID	0

struct chiptod_chipid {
	__be32		chip_id;
	__be32		flags;
#define CHIPTOD_ID_FLAGS_PRIMARY	0x02
#define CHIPTOD_ID_FLAGS_SECONDARY	0x01
#define CHIPTOD_ID_FLAGS_STATUS_MASK	0x0c
#define CHIPTOD_ID_FLAGS_STATUS_OK	0x04
#define CHIPTOD_ID_FLAGS_STATUS_NOK	0x08
} __packed;

/* Idata index 0: Chip Initialization data */
#define CHIPTOD_IDATA_CHIPINIT	1

struct chiptod_chipinit {
	__be32		ctrl_reg_internal;
	__be32		tod_ctrl_reg;
} __packed;

/*
 * MS VPD - Memory Description Tree
 *
 * One such structure pointing to the various memory arrays
 * along with other infos about the BCRs, Page Mover, XSCOM,...
 */
#define MSVPD_HDIF_SIG	"MS VPD"

/* Idata index 0: Mainstore address config */
#define MSVPD_IDATA_MS_ADDR_CONFIG	0

/* Mainstore Address Configuration */
struct msvpd_ms_addr_config {
	__be64	 max_configured_ms_address;
	__be64	 max_possible_ms_address;
	__be32	 deprecated;
	__be64	 mirrorable_memory_starting_address;
	__be64	 hrmor_stash_loc_address;
} __packed;

/* Idata index 1: Total configured mainstore */
#define MSVPD_IDATA_TOTAL_CONFIG_MS	1

struct msvpd_total_config_ms {
	__be64	 total_in_mb;
} __packed;

/* Idata index 2: Page mover and sync structure */
#define MSVPD_IDATA_PMOVER_SYNCHRO	2

struct msvpd_pmover_bsr_synchro {
	__be32		flags;
#define MSVPD_PMS_FLAG_HWLOCK_EN	0x80000000
#define MSVPD_PMS_FLAG_PMOVER_EN	0x40000000
#define MSVPD_PMS_FLAG_BSR_EN		0x20000000
#define MSVPD_PMS_FLAG_XSCOMBASE_VALID	0x10000000
	__be32		hwlocks_per_page;
	__be64		hwlock_addr;
	__be64		pmover_addr;
	__be64		bsr_addr;
	__be64		xscom_addr;
} __packed;

/* Idata index 3: Memory Trace Array */
#define MSVPD_IDATA_TRACE_AREAS		3
struct msvpd_trace {
	__be64 start, end;
	char reserved[16];
};

/* Idata index 4: UE Address Array */

/* Idata index 5: Hostboot reserved memory address range */
#define MSVPD_IDATA_HB_RESERVED_MEM	5
#define HB_RESERVE_MEM_LABEL_SIZE	64
struct msvpd_hb_reserved_mem {
#define MSVPD_HBRMEM_RANGE_TYPE	PPC_BITMASK32(0,7)
#define HBRMEM_CONTAINER_VERIFICATION_CODE 	0x3
	__be32		type_instance;
	__be64		start_addr;
	__be64		end_addr;
	__be32		label_size;
	uint8_t		label[HB_RESERVE_MEM_LABEL_SIZE];
	uint8_t		rw_perms;
#define HB_RESERVE_READABLE 0x80
#define HB_RESERVE_WRITEABLE 0x40
	uint8_t		reserved[7];
} __packed;

/* Child index 0: MS area child structure */
#define MSVPD_CHILD_MS_AREAS		0

/*
 * CEC I/O Hub FRU
 *
 * This is an array of CEC Hub FRU HDIF structures
 *
 * Each of these has some idata pointers to generic info about the
 * hub and a possible child pointer for daughter card.
 *
 * Actual ports are in the SLCA and need to be cross referenced
 *
 * Note that slots meant for the addition of GX+ adapters that
 * are currently unpopulated but support hotplug will have a
 * minimum "placeholder" entry, which will be fully populated
 * when the array is rebuild during concurrent maintenance.
 * This "placeholder" is called a "reservation".
 *
 * WARNING: The array rebuild by concurrent maintenance is not
 * guaranteed to be in the same order as the IPL array, not is
 * the order stable between concurrent maintenance operations.
 *
 * There's also a child pointer to daughter card structures but
 * we aren't going to handle that just yet.
 */
#define CECHUB_FRU_HDIF_SIG	"IO HUB"
#define IOKID_FRU_HDIF_SIG	"IO KID"
#define IOSLOT_FRU_HDIF_SIG	"IOSLOT"

/* Idata index 0: FRU ID data
 *
 * This is a generic struct spira_fru_id defined above
 */
#define CECHUB_FRU_ID_DATA		0

/* Idata index 1: ASCII Keyword VPD */
#define CECHUB_ASCII_KEYWORD_VPD	1

/* Idata index 2: Hub FRU ID data area */
#define CECHUB_FRU_ID_DATA_AREA		2

struct cechub_hub_fru_id {
	__be32		card_type;
#define CECHUB_FRU_TYPE_IOHUB_RSRV	0
#define CECHUB_FRU_TYPE_IOHUB_CARD	1
#define CECHUB_FRU_TYPE_CPU_CARD	2
#define CECHUB_FRU_TYPE_CEC_BKPLANE	3
#define CECHUB_FRU_TYPE_BKPLANE_EXT	4
	__be32		unused;
	__be16		total_chips;
	uint8_t		flags;
#define CECHUB_FRU_FLAG_HEADLESS	0x80 /* not connected to CPU */
#define CECHUB_FRU_FLAG_PASSTHROUGH	0x40 /* connected to passhtrough
						port of another hub */
	uint8_t		reserved;
	__be16		parent_hub_id;	/* chip instance number of the
					   hub that contains the passthrough
					   port this one is connected to */
	__be16		reserved2;
} __packed;


/* Idata index 3: IO HUB array */

#define CECHUB_FRU_IO_HUBS		3

/* This is an HDIF array of IO Hub structures */
struct cechub_io_hub {
	__be64		fmtc_address;
	__be32		fmtc_tce_size;
	__be16		hub_num;	/* unique hub number (I/O Hub ID) */
	uint8_t		flags;
#define CECHUB_HUB_FLAG_STATE_MASK	0xc0
#define CECHUB_HUB_FLAG_STATE_OK	0x00
#define CECHUB_HUB_FLAG_STATE_FAILURES	0x40
#define CECHUB_HUB_FLAG_STATE_NOT_INST	0x80
#define CECHUB_HUB_FLAG_STATE_UNUSABLE	0xc0
#define CECHUB_HUB_FLAG_MASTER_HUB	0x20 /* HDAT < v9.x only */
#define CECHUB_HUB_FLAG_GARD_MASK_VALID	0x08 /* HDAT < v9.x only */
#define CECHUB_HUB_FLAG_SWITCH_MASK_PDT	0x04 /* HDAT < v9.x only */
#define CECHUB_HUB_FLAG_FAB_BR0_PDT	0x02 /* HDAT < v9.x only */
#define CECHUB_HUB_FLAG_FAB_BR1_PDT	0x01 /* HDAT < v9.x only */
	uint8_t		nr_ports;	     /* HDAT < v9.x only */
	uint8_t		fab_br0_pdt;	/* p5ioc2 PCI-X or P8 PHB3's */
#define CECHUB_HUB_FAB_BR0_PDT_PHB0	0x80
#define CECHUB_HUB_FAB_BR0_PDT_PHB1	0x40
#define CECHUB_HUB_FAB_BR0_PDT_PHB2	0x20
#define CECHUB_HUB_FAB_BR0_PDT_PHB3	0x10
#define CECHUB_HUB_FAB_BR0_PDT_PHB4	0x08
#define CECHUB_HUB_FAB_BR0_PDT_PHB5	0x04
	uint8_t		fab_br1_pdt;	/* p5ioc2 & p7ioc PCI-E */
#define CECHUB_HUB_FAB_BR1_PDT_PHB0	0x80
#define CECHUB_HUB_FAB_BR1_PDT_PHB1	0x40
#define CECHUB_HUB_FAB_BR1_PDT_PHB2	0x20
#define CECHUB_HUB_FAB_BR1_PDT_PHB3	0x10
#define CECHUB_HUB_FAB_BR1_PDT_PHB4	0x08 /* p7ioc only */
#define CECHUB_HUB_FAB_BR1_PDT_PHB5	0x04 /* p7ioc only */
	__be16		iohub_id;	/* the type of hub */
#define CECHUB_HUB_MURANO		0x20ef	/* Murano from spec */
#define CECHUB_HUB_MURANO_SEGU		0x0001	/* Murano+Seguso from spec */
#define CECHUB_HUB_VENICE_WYATT		0x0010	/* Venice+Wyatt from spec */
#define CECHUB_HUB_NIMBUS_SFORAZ	0x0020	/* Nimbus+sforaz from spec */
#define CECHUB_HUB_NIMBUS_MONZA		0x0021	/* Nimbus+monza from spec */
#define CECHUB_HUB_NIMBUS_LAGRANGE	0x0022	/* Nimbus+lagrange from spec */
#define CECHUB_HUB_CUMULUS_DUOMO	0x0030	/* cumulus+duomo from spec */
#define CECHUB_HUB_AXONE_HOPPER		0x0040	/* axone+hopper */
#define CECHUB_HUB_RAINIER		0x0050
#define CECHUB_HUB_DENALI		0x0051
#define CECHUB_HUB_EVEREST		0x0052
	__be32		ec_level;
	__be32		aff_dom2;	/* HDAT < v9.x only */
	__be32		aff_dom3;	/* HDAT < v9.x only */
	__be64		reserved;
	__be32		proc_chip_id;

	union {
		/* HDAT < v9.x */
		struct {
			__be32		gx_index;	/* GX bus index on cpu */
			__be32		buid_ext;	/* BUID Extension */
			__be32		xscom_chip_id;	/* TORRENT ONLY */
		};
		/* HDAT >= v9.x */
		struct {
			__be32		reserved1;
			__be32		reserved2;
			__be16		reserved3;
			__be16		hw_topology;
		};
	};
	__be32		mrid;
	__be32		mem_map_vers;
	union {
		/* HDAT < v9.x */
		struct {
			__be64		gx_ctrl_bar0;
			__be64		gx_ctrl_bar1;
			__be64		gx_ctrl_bar2;
			__be64		gx_ctrl_bar3;
			__be64		gx_ctrl_bar4;
			__be32		sw_mask_pdt;
			__be16		gard_mask;
			__be16		gx_bus_speed;	/* Version 0x58 */
		};

		/* HDAT >= v9.x, HDIF version 0x6A adds phb_lane_eq with four
		 *               words per PHB (4 PHBs).
		 *
		 * HDAT >= 10.x, HDIF version 0x7A adds space for another
		 *               two PHBs (6 total) and the gen4 EQ values.
		 *
		 * HDAT >= 10.5x, HDIF version 0x8B adds space for the
		 *                gen5 EQ values.
		 */
		struct {
			/* Gen 3 PHB eq values, 6 PHBs */
			__be64		phb_lane_eq[6][4];

			/* Gen 4 PHB eq values */
			__be64		phb4_lane_eq[6][4];

			/* Gen 5 PHB eq values */
			__be64		phb5_lane_eq[6][4];
		};
	};
} __packed;

/* We support structures as small as 0x68 bytes */
#define CECHUB_IOHUB_MIN_SIZE	0x68

/* Child index 0: IO Daugther Card */
#define CECHUB_CHILD_IO_KIDS		0

/* Child index 1: PCIe Slot Mapping Information */
#define CECHUB_CHILD_IOSLOTS		1

#define IOSLOT_IDATA_SLOTMAP 0

struct slot_map_entry {
	__be16 entry_id;
	__be16 parent_id;
	uint8_t phb_index; /* only valid for ROOT and SWITCH_UP */

	uint8_t type;
#define SLOT_TYPE_ROOT_COMPLEX 0x0
#define SLOT_TYPE_SWITCH_UP    0x1
#define SLOT_TYPE_SWITCH_DOWN  0x2
#define SLOT_TYPE_BUILTIN      0x3

	uint8_t lane_swapped;
	uint8_t reserved;
	__be16	lane_mask;
	__be16  lane_reverse;

	/* what can I do with this? reference something under/vpd/ ? */
	__be16 slca_idx;

	__be16 mrw_slot_id;

	__be32 features;
#define SLOT_FEAT_SLOT 0x1

	uint8_t up_port;
	uint8_t down_port; /* the switch port this device is attached to */

	__be32 vendor_id;
	__be32 device_id;
	__be32 sub_vendor_id;
	__be32 sub_device_id;
	char name[8];
} __packed;

#define IOSLOT_IDATA_DETAILS 1

struct slot_map_details {
	__be16 entry;

	/* Phyp junk, ignore */
	uint8_t mgc_load_source;
	uint8_t hddw_order;
	__be16 mmio_size_32; /* In MB */
	__be16 mmio_size_64;
	__be16 dma_size_32;
	__be16 dma_size_64;

	uint8_t power_ctrl_type; /* slot power control source */
#define SLOT_PWR_NONE 0x0
#define SLOT_PWR_I2C  0x1

	uint8_t presence_det_type; /* slot presence detect source */
#define SLOT_PRESENCE_NONE 0x0
#define SLOT_PRESENCE_PCI  0x1
#define SLOT_PRESENCE_I2C  0x2

	uint8_t perst_ctl_type; /* slot PERST source */
#define SLOT_PERST_NONE      0x0
#define SLOT_PERST_PHB_OR_SW 0x1
#define SLOT_PERST_SW_GPIO   0x2
	uint8_t perst_gpio;

	__be16 max_power; /* in W? */

	__be32 slot_caps;
#define SLOT_CAP_LSI      0x01 /* phyp junk? */
#define SLOT_CAP_CAPI     0x02
#define SLOT_CAP_CCARD    0x04
#define SLOT_CAP_HOTPLUG  0x08
#define SLOT_CAP_SRIOV    0x10 /* phyp junk */
#define SLOT_CAP_ELLOCO   0x20 /* why is this seperate from the nvlink cap? */
#define SLOT_CAP_NVLINK   0x30

	__be16 reserved1;

	/* I2C Link IDs */
	__be32 i2c_power_ctl;
	__be32 i2c_pgood;
	__be32 i2c_cable_card; /* opencapi presence detect? */
	__be32 i2c_mex_fpga;
};

/*
 * IO KID is a dauther card structure
 */
#define IOKID_FRU_ID_DATA	0
#define IOKID_KW_VPD		1

/*
 * CPU Controls Legacy Structure
 */
struct cpu_ctl_legacy {
	__be64 addr;
	__be64 size;
} __packed;

/*
 * CPU Control Legacy table
 *
 * Format of this table is defined in FIPS PHYP Attn spec.
 */
struct cpu_ctl_legacy_table {
	struct cpu_ctl_legacy spat;
	struct cpu_ctl_legacy sp_attn_area1;
	struct cpu_ctl_legacy sp_attn_area2;
	struct cpu_ctl_legacy hsr_area;
	struct cpu_ctl_legacy reserved[12];
} __packed;

/*
 * CPU Controls Header Structure
 */
#define CPU_CTL_HDIF_SIG	"CPUCTL"
struct cpu_ctl_init_data {
	struct HDIF_common_hdr		hdr;
	struct HDIF_idata_ptr		cpu_ctl;
	uint8_t				reserved[8];
	struct cpu_ctl_legacy_table	cpu_ctl_lt;
} __packed __align(0x10);

/*
 * Slot Location Code Array (aka SLCA)
 *
 * This is a pile of location codes referenced by various other
 * structures such as the IO Hubs for things on the CEC. Not
 * everything in there is a physical port. The SLCA is actually
 * a tree which represent the topology of the system.
 *
 * The tree works as follow: A parent has a pointer to the first
 * child. A child has a pointer to its parent. Siblings are
 * consecutive entries.
 *
 * Note: If we ever support concurrent maintenance... this is
 * completely rebuilt, invalidating all indices, though other
 * structures that may reference SLCA by index will be rebuilt
 * as well.
 *
 * Note that a lot of that stuff is based on VPD documentation
 * such as the identification keywords. I will list the ones
 * I manage to figure out without the doc separately.
 */
#define SLCA_HDIF_SIG	"SLCA  "

/* Idata index 0 : SLCA root pointer
 *
 * The SLCA array is an HDIF array of all the entries. The tree
 * structure is based on indices inside the entries and order of
 * the entries
 */
#define SLCA_IDATA_ARRAY	0

#define SLCA_ROOT_INDEX		0

/* Note: An "index" (or idx) is always an index into the SLCA array
 * and "id" is a reference to some other object.
 */
struct slca_entry {
	__be16		my_index;	/* redundant, useful */
	__be16		rsrc_id;	/* formerly VPD port number */
	uint8_t		fru_id[2];	/* ASCII VPD ID */
#define SLCA_ROOT_VPD_ID	VPD_ID('V','V')
#define SLCA_SYSTEM_VPD_ID	VPD_ID('S','V')
#define SLCA_SAI_INDICATOR_ID	VPD_ID('S','A')
	__be16		parent_index;	/* Parent entry index */
	uint8_t		flags;
#define SLCA_FLAG_NON_FUNCTIONAL	0x02	/* For redundant entries */
#define SLCA_FLAG_IMBEDDED		0x01	/* not set => pluggable */
	uint8_t		old_nr_child;	/* Legacy: Nr of children */
	__be16		child_index;	/* First child index */
	__be16		child_rsrc_id;	/* Resource ID of first child */
	uint8_t		loc_code_allen;	/* Alloc len of loc code */
	uint8_t		loc_code_len;	/* Loc code len */
	uint8_t		loc_code[LOC_CODE_SIZE]; /* NULL terminated (thus max 79 chr) */
	__be16		first_dup_idx;	/* First redundant resource index */
	uint8_t		nr_dups;	/* Number of redundant entries */
	uint8_t		reserved;
	__be16		nr_child;	/* New version */
	uint8_t		install_indic;	/* Installed indicator */
#define SLCA_INSTALL_NO_HW_PDT		1 /* No HW presence detect */
#define SLCA_INSTALL_INSTALLED		2
#define SLCA_INSTALL_NOT_INSTALLED	3
	uint8_t		vpd_collected;
#define SLCA_VPD_COLLECTED		2
#define SLCA_VPD_NOT_COLLECTED		3
} __packed;

/*
 * System VPD
 */
#define SYSVPD_HDIF_SIG	"SYSVPD"

/* Idata index 0 : FRU ID Data */
#define SYSVPD_IDATA_FRU_ID	0

/* Idata index 1 : Keyword VPD */
#define SYSVPD_IDATA_KW_VPD	1

/* Idata index 2 : Operational status */
#define SYSVPD_IDATA_OP_STATUS	2

/*
 * FRU keyword VPD structure
 */
#define FRUVPD_HDIF_SIG	"FRUVPD"

/* Idata index 0 : FRU ID Data */
#define FRUVPD_IDATA_FRU_ID	0

/* Idata index 1 : Keyword VPD */
#define FRUVPD_IDATA_KW_VPD	1

/* Idata index 2 : Operational status */
#define FRUVPD_IDATA_OP_STATUS	2


/*
 * SPPCIA structure. The SPIRA contain an array of these, one
 * per processor core
 */
#define SPPCIA_HDIF_SIG	"SPPCIA"

/* Idata index 0 : Core unique data */
#define SPPCIA_IDATA_CORE_UNIQUE	0

struct sppcia_core_unique {
	__be32 reserved;
	__be32 proc_fru_id;
	__be32 hw_proc_id;
#define CPU_ID_VERIFY_MASK			0xC0000000
#define CPU_ID_VERIFY_SHIFT			30
#define CPU_ID_VERIFY_USABLE_NO_FAILURES	0
#define CPU_ID_VERIFY_USABLE_FAILURES		1
#define CPU_ID_VERIFY_NOT_INSTALLED		2
#define CPU_ID_VERIFY_UNUSABLE			3
#define CPU_ID_SECONDARY_THREAD			0x20000000
#define CPU_ID_PCIA_RESERVED			0x10000000
#define CPU_ID_NUM_SECONDARY_THREAD_MASK	0x00FF0000
#define CPU_ID_NUM_SECONDARY_THREAD_SHIFT	16
	__be32 verif_exist_flags;
	__be32 chip_ec_level;
	__be32 proc_chip_id;
	__be32 reserved2;
	__be32 reserved3;
	__be32 reserved4;
	__be32 hw_module_id;
	__be64 reserved5;
	__be32 reserved6;
	__be32 reserved7;
	__be32 reserved8;
	__be32 ccm_node_id;
	__be32 hw_card_id;
	__be32 internal_drawer_node_id;
	__be32 drawer_book_octant_blade_id;
	__be32 memory_interleaving_scope;
	__be32 lco_target;
	__be32 reserved9;
} __packed;

/* Idata index 1 : CPU Time base structure */
#define SPPCIA_IDATA_TIMEBASE		1

struct sppcia_cpu_timebase {
	__be32 cycle_time;
	__be32 time_base;
	__be32 actual_clock_speed;
	__be32 memory_bus_frequency;
} __packed;

/* Idata index 2 : CPU Cache Size Structure */
#define SPPCIA_IDATA_CPU_CACHE		2

struct sppcia_cpu_cache {
	__be32 icache_size_kb;
	__be32 icache_line_size;
	__be32 l1_dcache_size_kb;
	__be32 l1_dcache_line_size;
	__be32 l2_dcache_size_kb;
	__be32 l2_line_size;
	__be32 l3_dcache_size_kb;
	__be32 l3_line_size;
	__be32 dcache_block_size;
	__be32 icache_block_size;
	__be32 dcache_assoc_sets;
	__be32 icache_assoc_sets;
	__be32 dtlb_entries;
	__be32 dtlb_assoc_sets;
	__be32 itlb_entries;
	__be32 itlb_assoc_sets;
	__be32 reservation_size;
	__be32 l2_cache_assoc_sets;
	__be32 l35_dcache_size_kb;
	__be32 l35_cache_line_size;
} __packed;


/* Idata index 3 : Thread Array Data
 *
 * HDIF array of
 */
#define SPPCIA_IDATA_THREAD_ARRAY	3

struct sppcia_cpu_thread {
	__be32 proc_int_line;
	__be32 phys_thread_id;
	__be64 ibase;
	__be32 pir;
} __packed;

/* Idata index 4 : CPU Attributes */
#define SPPCIA_IDATA_CPU_ATTR		4

struct sppcia_cpu_attr {
#define CPU_ATTR_UNIFIED_PL1	0x80
#define CPU_ATTR_SPLIT_TLB	0x40
#define CPU_ATTR_TLBIA		0x20
#define CPU_ATTR_PERF_MONITOR	0x10
#define CPU_ATTR_EXTERN_CONT	0x02
	__be32 attr;
} __packed;

/*
 * Processor Chip Related Data. The SPIRA contain an array of these, one
 * per chip
 */
#define SPPCRD_HDIF_SIG	"SPPCRD"

/* Idata index 0 : Chip info */
#define SPPCRD_IDATA_CHIP_INFO	0

struct sppcrd_chip_info {
	__be32 proc_chip_id;
	__be32 verif_exist_flags;
#define CHIP_VERIFY_MASK			0xC0000000
#define CHIP_VERIFY_SHIFT			30
#define CHIP_VERIFY_USABLE_NO_FAILURES		0
#define CHIP_VERIFY_USABLE_FAILURES		1
#define CHIP_VERIFY_NOT_INSTALLED		2
#define CHIP_VERIFY_UNUSABLE			3
#define CHIP_VERIFY_MASTER_PROC			PPC_BIT32(4)
	__be32 nx_state;
	__be32 pore_state;
	__be32 xscom_id;
	/* Version 0xA */
	__be32 reserved;
	__be32 dbob_id;
	__be32 occ_state;
	/* Version 0xC - none of these are used */
	__be32 processor_fru_id;
	__be32 chip_ec_level;
	__be32 hw_module_id;
	__be32 hw_card_id;
	__be32 internal_drawer_nid;
	__be32 ccm_nid;
	/* Version 0xD */
	__be32 capp0_func_state;
	/* Version 0xE */
	__be32 capp1_func_state;
	/* *possibly* from Version 0x20 - check spec */
	__be32 stop_levels;
	/* From latest version (possibly 0x21 and later) */
	__be32 sw_xstop_fir_scom;
	uint8_t sw_xstop_fir_bitpos;
	/* Latest version for P10 */
#define	CHIP_MAX_TOPOLOGY_ENTRIES	32
	uint8_t topology_id_table[CHIP_MAX_TOPOLOGY_ENTRIES];
	uint8_t	primary_topology_loc;	/* Index in topology_id_table */
	__be32  abc_bus_speed;	/* SMP A */
	__be32  wxyz_bus_speed;	/* SMP X */
	uint8_t	fab_topology_id;/* topology id associated with the chip. */
} __packed;

/* Idata index 1 : Chip TOD */
#define SPPCRD_IDATA_CHIP_TOD	1

struct sppcrd_chip_tod {
	__be32 flags;
	/* CHIPTOD_ID_... values */
	__be32 ctrl_reg_internal;
	__be32 tod_ctrl_reg;
} __packed;

/* Idata index 2 : FRU ID */
#define SPPCRD_IDATA_FRU_ID	2

/* Idata index 3 : ASCII Keyword data */
#define SPPCRD_IDATA_KW_VPD	3

/* Idata index 4 : Module VPD */
#define SPPCRD_IDATA_MODULE_VPD	4

/* Idata index 5 : Chip attached I2C devices */
#define SPPCRD_IDATA_HOST_I2C	5

/* Idata index 5 : Chip attached I2C devices */
#define SPPCRD_IDATA_PNOR	6

/* Idata index 6 : OpenCAPI/NVlink info */
#define SPPCRD_IDATA_SMP_LINK	7
struct sppcrd_smp_link {
	__be32 link_id;
	__be32 usage;
#define SMP_LINK_USE_NONE 	0
#define SMP_LINK_USE_GPU	1
#define SMP_LINK_USE_OPENCAPI	2
#define SMP_LINK_USE_INTERPOSER 3
#define SMP_LINK_USE_DRAWER	4
#define SMP_LINK_USE_D2D	5 /* GPU to GPU */
	__be32 brick_id;
	__be32 lane_mask;

	/* bonded pci slots (mostly a NVLink thing) */
	__be16 pci_slot_idx;
	__be16 pci_sideband_slot_idx;

	__be16 slca_idx; /* SLCA index of the *external* port */
	__be16 opt_id;

	/* nvlink/ocapi detection devices */
	__be32 i2c_link_cable;
	__be32 i2c_presence;
	__be32 i2c_micro;
	uint8_t link_speed;
	uint8_t occ_flag_bit;
	__be16 gpu_slca;
} __packed;

/* Idata index 8 : chip EC Level array */
#define SPPCRD_IDATA_EC_LEVEL	8

struct sppcrd_ecid {
	__be32	chip_id;
	__be32	ec_level;
	__be64	low;	/* Processor ECID bit 0-63 */
	__be64	high;	/* Processor ECID bit 64-127 */
} __packed;

/*
 * Host Services Data.
 */
#define HSERV_HDIF_SIG	"HOSTSR"

/* Idata index 0 : System attribute data */
#define HSERV_IDATA_SYS_ATTR	0

/* IPMI sensors mapping data */
#define IPMI_SENSORS_HDIF_SIG	"FRUSE "

/* Idata index 0 : Sensor mapping data */
#define IPMI_SENSORS_IDATA_SENSORS	0

struct ipmi_sensors_data {
	__be32	slca_index;
	uint8_t	type;
	uint8_t	id;
	uint8_t entity_id;
	uint8_t reserved;
} __packed;

struct ipmi_sensors {
	__be32	count;
	struct ipmi_sensors_data data[];
} __packed;

/* Idata index 1 : LED - sensors ID mapping data */
#define IPMI_SENSORS_IDATA_LED		1

/*
 * Node Secure and Trusted Boot Related Data
 */
#define STB_HDIF_SIG	"TPMREL"

/*
 * Idata index 0 : Secure Boot and TPM Instance Info
 *
 * There can be multiple entries with each entry corresponding to
 * a master processor that has a TPM device
 */
#define TPMREL_IDATA_SECUREBOOT_TPM_INFO	0

struct secureboot_tpm_info {
	__be32 chip_id;
	__be32 dbob_id;
	uint8_t locality1;
	uint8_t locality2;
	uint8_t locality3;
	uint8_t locality4;
#define TPM_PRESENT_AND_FUNCTIONAL	0x01
#define TPM_PRESENT_AND_NOT_FUNCTIONAL	0x02
#define TPM_NOT_PRESENT			0x03
	uint8_t tpm_status;
	uint8_t reserved[3];
	/* zero indicates no tpm log data */
	__be32 srtm_log_offset;
	__be32 srtm_log_size;
	/* zero indicates no tpm log data */
	__be32 drtm_log_offset;
	__be32 drtm_log_size;
} __packed;

/* Idata index 2: Hash and Verification Function Offsets Array */
#define TPMREL_IDATA_HASH_VERIF_OFFSETS 	2

struct hash_and_verification {
#define TPMREL_HV_SHA512	0x00
#define TPMREL_HV_VERIFY	0x01
	__be32 type;
	__be32 version;
	__be32 dbob_id;
	__be32 offset;
} __packed;

static inline const char *cpu_state(u32 flags)
{
	switch ((flags & CPU_ID_VERIFY_MASK) >> CPU_ID_VERIFY_SHIFT) {
	case CPU_ID_VERIFY_USABLE_NO_FAILURES:
		return "OK";
	case CPU_ID_VERIFY_USABLE_FAILURES:
		return "FAILURES";
	case CPU_ID_VERIFY_NOT_INSTALLED:
		return "NOT-INSTALLED";
	case CPU_ID_VERIFY_UNUSABLE:
		return "UNUSABLE";
	}
	return "**UNKNOWN**";
}
#endif /* __SPIRA_H */
