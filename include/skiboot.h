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

#ifndef __SKIBOOT_H
#define __SKIBOOT_H

#include <compiler.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <bitutils.h>
#include <types.h>

#include <ccan/container_of/container_of.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/str/str.h>

#include <mem-map.h>
#include <op-panel.h>
#include <platform.h>

/* Special ELF sections */
#define __force_data		__section(".force.data")

/* Readonly section start and end. */
extern char __rodata_start[], __rodata_end[];

static inline bool is_rodata(const void *p)
{
	return ((const char *)p >= __rodata_start && (const char *)p < __rodata_end);
}

/* Debug descriptor. This structure is pointed to by the word at offset
 * 0x80 in the sapphire binary
 */
struct debug_descriptor {
	u8	eye_catcher[8];	/* "OPALdbug" */
#define DEBUG_DESC_VERSION	1
	u32	version;
	u8	console_log_levels;	/* high 4 bits in memory,
					 * low 4 bits driver (e.g. uart). */
	u8	reserved1;
	u16	reserved2;
	u32	reserved[2];

	/* Memory console */
	u64	memcons_phys;
	u32	memcons_tce;
	u32	memcons_obuf_tce;
	u32	memcons_ibuf_tce;

	/* Traces */
	u64	trace_mask;
	u32	num_traces;
#define DEBUG_DESC_MAX_TRACES	256
	u64	trace_phys[DEBUG_DESC_MAX_TRACES];
	u32	trace_size[DEBUG_DESC_MAX_TRACES];
	u32	trace_tce[DEBUG_DESC_MAX_TRACES];
};
extern struct debug_descriptor debug_descriptor;

/* Console logging */
#define PR_EMERG	0
#define PR_ALERT	1
#define PR_CRIT		2
#define PR_ERR		3
#define PR_WARNING	4
#define PR_NOTICE	5
#define PR_PRINTF	PR_NOTICE
#define PR_INFO		6
#define PR_DEBUG	7
#define PR_TRACE	8
#define PR_INSANE	9
void prlog(int log_level, const char* fmt, ...) __attribute__((format (printf, 2, 3)));
#define prerror(fmt...)	do { prlog(PR_ERR, fmt); } while(0)

/* Location codes  -- at most 80 chars with null termination */
#define LOC_CODE_SIZE	80

enum ipl_state {
	ipl_initial		= 0x00000000,
	ipl_opl_sent		= 0x00000001,
	ipl_got_continue	= 0x00000002,
	ipl_got_new_role	= 0x00000004,
	ipl_got_caps		= 0x00000008,
	ipl_got_fsp_functional	= 0x00000010
};
extern enum ipl_state ipl_state;

/* Processor generation */
enum proc_gen {
	proc_gen_unknown,
	proc_gen_p7,		/* P7 and P7+ */
	proc_gen_p8,
};
extern enum proc_gen proc_gen;

/* Boot stack top */
extern void *boot_stack_top;

/* For use by debug code */
extern void backtrace(void);
extern void __backtrace(char *bt_buf, int bt_buf_len);

/* Convert a 4-bit number to a hex char */
extern char tohex(uint8_t nibble);

/* Bit position of the most significant 1-bit (LSB=0, MSB=63) */
static inline int ilog2(unsigned long val)
{
	int left_zeros;

	asm volatile ("cntlzd %0,%1" : "=r" (left_zeros) : "r" (val));

	return 63 - left_zeros;
}

static inline bool is_pow2(unsigned long val)
{
	return val == (1ul << ilog2(val));
}

#define lo32(x)	((x) & 0xffffffff)
#define hi32(x)	(((x) >> 32) & 0xffffffff)

/* WARNING: _a *MUST* be a power of two */
#define ALIGN_UP(_v, _a)	(((_v) + (_a) - 1) & ~((_a) - 1))
#define ALIGN_DOWN(_v, _a)	((_v) & ~((_a) - 1))

/* TCE alignment */
#define TCE_PSIZE	0x1000
#define TCE_MASK	0xfff

/* Not the greatest variants but will do for now ... */
#define MIN(a, b)	((a) < (b) ? (a) : (b))
#define MAX(a, b)	((a) > (b) ? (a) : (b))

/* Clean the stray high bit which the FSP inserts: we only have 52 bits real */
static inline u64 cleanup_addr(u64 addr)
{
	return addr & ((1ULL << 52) - 1);
}

/* Start the kernel */
extern void start_kernel(uint64_t entry, void* fdt,
			 uint64_t mem_top) __noreturn;
extern void start_kernel32(uint64_t entry, void* fdt,
			   uint64_t mem_top) __noreturn;
extern void start_kernel_secondary(uint64_t entry) __noreturn;

/* Get description of machine from HDAT and create device-tree */
extern void parse_hdat(bool is_opal, uint32_t master_cpu);

/* Root of device tree. */
extern struct dt_node *dt_root;

/* Generated git id. */
extern const char gitid[];

/* Fast reboot support */
extern void fast_reset(void);
extern void __secondary_cpu_entry(void);
extern void load_and_boot_kernel(bool is_reboot);
extern void cleanup_tlb(void);
extern void init_shared_sprs(void);
extern void init_replicated_sprs(void);

/* Various probe routines, to replace with an initcall system */
extern void probe_p5ioc2(void);
extern void probe_p7ioc(void);
extern void probe_phb3(void);
extern void uart_init(bool enable_interrupt);
extern void homer_init(void);
extern void add_cpu_idle_state_properties(void);
extern void occ_pstates_init(void);
extern void slw_init(void);
extern void occ_fsp_init(void);

/* NVRAM support */
extern void nvram_init(void);
extern void nvram_read_complete(bool success);

/* NVRAM on flash helper */
struct flash_chip;
extern int flash_nvram_init(struct flash_chip *chip, uint32_t start,
			    uint32_t size);

/* UART interrupt */
extern void uart_irq(void);

/* Flatten device-tree */
extern void *create_dtb(const struct dt_node *root);

/* SLW reinit function for switching core settings */
extern int64_t slw_reinit(uint64_t flags);

/* Fallback fake RTC */
extern void fake_rtc_init(void);

#endif /* __SKIBOOT_H */

