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

#include <skiboot.h>
#include <fsp.h>
#include <fsp-sysparam.h>
#include <psi.h>
#include <memory.h>
#include <chiptod.h>
#include <nx.h>
#include <cpu.h>
#include <processor.h>
#include <xscom.h>
#include <device_tree.h>
#include <opal.h>
#include <opal-msg.h>
#include <elf.h>
#include <io.h>
#include <cec.h>
#include <device.h>
#include <pci.h>
#include <lpc.h>
#include <chip.h>
#include <interrupts.h>
#include <mem_region.h>
#include <trace.h>
#include <console.h>
#include <fsi-master.h>
#include <centaur.h>
#include <libfdt/libfdt.h>
#include <hostservices.h>

/*
 * Boot semaphore, incremented by each CPU calling in
 *
 * Forced into data section as it will be used before BSS is initialized
 */
enum ipl_state ipl_state = ipl_initial;
enum proc_gen proc_gen;

static uint64_t kernel_entry;
static bool kernel_32bit;
static void *fdt;

struct debug_descriptor debug_descriptor = {
	.eye_catcher	= "OPALdbug",
	.version	= DEBUG_DESC_VERSION,
	.memcons_phys	= (uint64_t)&memcons,
	.trace_mask	= 0, /* All traces disabled by default */
	.console_log_levels = (PR_DEBUG << 4) | PR_NOTICE,
};

static bool try_load_elf64_le(struct elf_hdr *header)
{
	struct elf64_hdr *kh = (struct elf64_hdr *)header;
	uint64_t load_base = (uint64_t)kh;
	struct elf64_phdr *ph;
	unsigned int i;

	printf("INIT: 64-bit LE kernel discovered\n");

	/* Look for a loadable program header that has our entry in it
	 *
	 * Note that we execute the kernel in-place, we don't actually
	 * obey the load informations in the headers. This is expected
	 * to work for the Linux Kernel because it's a fairly dumb ELF
	 * but it will not work for any ELF binary.
	 */
	ph = (struct elf64_phdr *)(load_base + le64_to_cpu(kh->e_phoff));
	for (i = 0; i < le16_to_cpu(kh->e_phnum); i++, ph++) {
		if (le32_to_cpu(ph->p_type) != ELF_PTYPE_LOAD)
			continue;
		if (le64_to_cpu(ph->p_vaddr) > le64_to_cpu(kh->e_entry) ||
		    (le64_to_cpu(ph->p_vaddr) + le64_to_cpu(ph->p_memsz)) <
		    le64_to_cpu(kh->e_entry))
			continue;

		/* Get our entry */
		kernel_entry = le64_to_cpu(kh->e_entry) -
			le64_to_cpu(ph->p_vaddr) + le64_to_cpu(ph->p_offset);
		break;
	}

	if (!kernel_entry) {
		prerror("INIT: Failed to find kernel entry !\n");
		return false;
	}
	kernel_entry += load_base;
	kernel_32bit = false;

	printf("INIT: 64-bit kernel entry at 0x%llx\n", kernel_entry);

	return true;
}

static bool try_load_elf64(struct elf_hdr *header)
{
	struct elf64_hdr *kh = (struct elf64_hdr *)header;
	uint64_t load_base = (uint64_t)kh;
	struct elf64_phdr *ph;
	unsigned int i;

	/* Check it's a ppc64 LE ELF */
	if (kh->ei_ident == ELF_IDENT		&&
	    kh->ei_data == ELF_DATA_LSB		&&
	    kh->e_machine == le16_to_cpu(ELF_MACH_PPC64)) {
		return try_load_elf64_le(header);
	}

	/* Check it's a ppc64 ELF */
	if (kh->ei_ident != ELF_IDENT		||
	    kh->ei_data != ELF_DATA_MSB		||
	    kh->e_machine != ELF_MACH_PPC64) {
		prerror("INIT: Kernel doesn't look like an ppc64 ELF\n");
		return false;
	}

	/* Look for a loadable program header that has our entry in it
	 *
	 * Note that we execute the kernel in-place, we don't actually
	 * obey the load informations in the headers. This is expected
	 * to work for the Linux Kernel because it's a fairly dumb ELF
	 * but it will not work for any ELF binary.
	 */
	ph = (struct elf64_phdr *)(load_base + kh->e_phoff);
	for (i = 0; i < kh->e_phnum; i++, ph++) {
		if (ph->p_type != ELF_PTYPE_LOAD)
			continue;
		if (ph->p_vaddr > kh->e_entry ||
		    (ph->p_vaddr + ph->p_memsz) < kh->e_entry)
			continue;

		/* Get our entry */
		kernel_entry = kh->e_entry - ph->p_vaddr + ph->p_offset;
		break;
	}

	if (!kernel_entry) {
		prerror("INIT: Failed to find kernel entry !\n");
		return false;
	}
	kernel_entry += load_base;
	kernel_32bit = false;

	printf("INIT: 64-bit kernel entry at 0x%llx\n", kernel_entry);

	return true;
}

static bool try_load_elf32_le(struct elf_hdr *header)
{
	struct elf32_hdr *kh = (struct elf32_hdr *)header;
	uint64_t load_base = (uint64_t)kh;
	struct elf32_phdr *ph;
	unsigned int i;

	printf("INIT: 32-bit LE kernel discovered\n");

	/* Look for a loadable program header that has our entry in it
	 *
	 * Note that we execute the kernel in-place, we don't actually
	 * obey the load informations in the headers. This is expected
	 * to work for the Linux Kernel because it's a fairly dumb ELF
	 * but it will not work for any ELF binary.
	 */
	ph = (struct elf32_phdr *)(load_base + le32_to_cpu(kh->e_phoff));
	for (i = 0; i < le16_to_cpu(kh->e_phnum); i++, ph++) {
		if (le32_to_cpu(ph->p_type) != ELF_PTYPE_LOAD)
			continue;
		if (le32_to_cpu(ph->p_vaddr) > le32_to_cpu(kh->e_entry) ||
		    (le32_to_cpu(ph->p_vaddr) + le32_to_cpu(ph->p_memsz)) <
		    le32_to_cpu(kh->e_entry))
			continue;

		/* Get our entry */
		kernel_entry = le32_to_cpu(kh->e_entry) -
			le32_to_cpu(ph->p_vaddr) + le32_to_cpu(ph->p_offset);
		break;
	}

	if (!kernel_entry) {
		prerror("INIT: Failed to find kernel entry !\n");
		return false;
	}

	kernel_entry += load_base;
	kernel_32bit = true;

	printf("INIT: 32-bit kernel entry at 0x%llx\n", kernel_entry);

	return true;
}

static bool try_load_elf32(struct elf_hdr *header)
{
	struct elf32_hdr *kh = (struct elf32_hdr *)header;
	uint64_t load_base = (uint64_t)kh;
	struct elf32_phdr *ph;
	unsigned int i;

	/* Check it's a ppc32 LE ELF */
	if (header->ei_ident == ELF_IDENT		&&
	    header->ei_data == ELF_DATA_LSB		&&
	    header->e_machine == le16_to_cpu(ELF_MACH_PPC32)) {
		return try_load_elf32_le(header);
	}

	/* Check it's a ppc32 ELF */
	if (header->ei_ident != ELF_IDENT		||
	    header->ei_data != ELF_DATA_MSB		||
	    header->e_machine != ELF_MACH_PPC32) {
		prerror("INIT: Kernel doesn't look like an ppc32 ELF\n");
		return false;
	}

	/* Look for a loadable program header that has our entry in it
	 *
	 * Note that we execute the kernel in-place, we don't actually
	 * obey the load informations in the headers. This is expected
	 * to work for the Linux Kernel because it's a fairly dumb ELF
	 * but it will not work for any ELF binary.
	 */
	ph = (struct elf32_phdr *)(load_base + kh->e_phoff);
	for (i = 0; i < kh->e_phnum; i++, ph++) {
		if (ph->p_type != ELF_PTYPE_LOAD)
			continue;
		if (ph->p_vaddr > kh->e_entry ||
		    (ph->p_vaddr + ph->p_memsz) < kh->e_entry)
			continue;

		/* Get our entry */
		kernel_entry = kh->e_entry - ph->p_vaddr + ph->p_offset;
		break;
	}

	if (!kernel_entry) {
		prerror("INIT: Failed to find kernel entry !\n");
		return false;
	}

	kernel_entry += load_base;
	kernel_32bit = true;

	printf("INIT: 32-bit kernel entry at 0x%llx\n", kernel_entry);

	return true;
}

/* LID numbers. For now we hijack some of pHyp's own until i figure
 * out the whole business with the MasterLID
 */
#define KERNEL_LID_PHYP	0x80a00701
#define KERNEL_LID_OPAL	0x80f00101

extern char __builtin_kernel_start[];
extern char __builtin_kernel_end[];
extern uint64_t boot_offset;

static bool load_kernel(void)
{
	struct elf_hdr *kh;
	uint32_t lid;
	size_t ksize;
	const char *ltype;

	ltype = dt_prop_get_def(dt_root, "lid-type", NULL);

	/* No lid-type, assume stradale, currently pre-loaded at fixed
	 * address
	 */
	if (!ltype) {
		printf("No lid-type property, assuming FSP-less setup\n");
		ksize = __builtin_kernel_end - __builtin_kernel_start;
		if (ksize) {
			/* Move the built-in kernel up */
			uint64_t builtin_base =
				((uint64_t)__builtin_kernel_start) -
				SKIBOOT_BASE + boot_offset;    
			printf("Using built-in kernel\n");
			memmove(KERNEL_LOAD_BASE, (void*)builtin_base, ksize);
		} else
			printf("Assuming kernel at 0x%p\n", KERNEL_LOAD_BASE);
	} else {
		ksize = KERNEL_LOAD_SIZE;

		/* First try to load an OPAL secondary LID always */
		lid = fsp_adjust_lid_side(KERNEL_LID_OPAL);
		printf("Trying to load OPAL secondary LID...\n");
		if (fsp_fetch_data(0, FSP_DATASET_NONSP_LID, lid, 0,
				   KERNEL_LOAD_BASE, &ksize) != 0) {	
			if (!strcmp(ltype, "opal")) {
				prerror("Failed to load in OPAL mode...\n");
				return false;
			}
			printf("Trying to load as PHYP LID...\n");
			lid = fsp_adjust_lid_side(KERNEL_LID_PHYP);
			ksize = KERNEL_LOAD_SIZE;
			if (fsp_fetch_data(0, FSP_DATASET_NONSP_LID, lid, 0,
					   KERNEL_LOAD_BASE, &ksize) != 0) {	
				prerror("Failed to load kernel\n");
				return false;
			}
		}
	}

	printf("INIT: Kernel loaded, size: %zu bytes (0 = unknown preload)\n",
	       ksize);

	kh = (struct elf_hdr *)KERNEL_LOAD_BASE;
	if (kh->ei_class == ELF_CLASS_64)
		return try_load_elf64(kh);
	else if (kh->ei_class == ELF_CLASS_32)
		return try_load_elf32(kh);

	printf("INIT: Neither ELF32 not ELF64 ?\n");
	return false;
}

void __noreturn load_and_boot_kernel(bool is_reboot)
{
	const struct dt_property *memprop;
	uint64_t mem_top;

	memprop = dt_find_property(dt_root, DT_PRIVATE "maxmem");
	if (memprop)
		mem_top = (u64)dt_property_get_cell(memprop, 0) << 32
			| dt_property_get_cell(memprop, 1);
	else /* XXX HB hack, might want to calc it */
		mem_top = 0x40000000;

	op_display(OP_LOG, OP_MOD_INIT, 0x000A);

	/* Load kernel LID */
	if (!load_kernel()) {
		op_display(OP_FATAL, OP_MOD_INIT, 1);
		abort();
	}

	if (!is_reboot) {
		/* We wait for the nvram read to complete here so we can
		 * grab stuff from there such as the kernel arguments
		 */
		fsp_nvram_wait_open();

		/* Wait for FW VPD data read to complete */
		fsp_code_update_wait_vpd(true);
	}
	fsp_console_select_stdout();

	/* 
	 * OCC takes few secs to boot.  Call this as late as
	 * as possible to avoid delay.
	 */
	occ_pstates_init();

	/* Set kernel command line argument if specified */
#ifdef KERNEL_COMMAND_LINE
	dt_add_property_string(dt_chosen, "bootargs", KERNEL_COMMAND_LINE);
#endif

	op_display(OP_LOG, OP_MOD_INIT, 0x000B);

	/* Create the device tree blob to boot OS. */
	fdt = create_dtb(dt_root);
	if (!fdt) {
		op_display(OP_FATAL, OP_MOD_INIT, 2);
		abort();
	}

	op_display(OP_LOG, OP_MOD_INIT, 0x000C);

	/* Start the kernel */
	if (!is_reboot)
		op_panel_disable_src_echo();

	/* Clear SRCs on the op-panel when Linux starts */
	op_panel_clear_src();

	cpu_give_self_os();

	printf("INIT: Starting kernel at 0x%llx, fdt at %p (size 0x%x)\n",
	       kernel_entry, fdt, fdt_totalsize(fdt));

	fdt_set_boot_cpuid_phys(fdt, this_cpu()->pir);
	if (kernel_32bit)
		start_kernel32(kernel_entry, fdt, mem_top);
	start_kernel(kernel_entry, fdt, mem_top);
}

static void dt_fixups(void)
{
	struct dt_node *n;
	struct dt_node *primary_lpc = NULL;

	/* lpc node missing #address/size cells. Also pick one as
	 * primary for now (TBD: How to convey that from HB)
	 */
	dt_for_each_compatible(dt_root, n, "ibm,power8-lpc") {
		if (!primary_lpc || dt_has_node_property(n, "primary", NULL))
			primary_lpc = n;
		if (dt_has_node_property(n, "#address-cells", NULL))
			break;
		dt_add_property_cells(n, "#address-cells", 2);
		dt_add_property_cells(n, "#size-cells", 1);
		dt_add_property_strings(n, "status", "ok");
	}

	/* Missing "primary" property in LPC bus */
	if (primary_lpc && !dt_has_node_property(primary_lpc, "primary", NULL))
		dt_add_property(primary_lpc, "primary", NULL, 0);

	/* Missing "scom-controller" */
	dt_for_each_compatible(dt_root, n, "ibm,xscom") {
		if (!dt_has_node_property(n, "scom-controller", NULL))
			dt_add_property(n, "scom-controller", NULL, 0);
	}
}

static void add_arch_vector(void)
{
	/**
	 * vec5 = a PVR-list : Number-of-option-vectors :
	 *	  option-vectors[Number-of-option-vectors + 1]
	 */
	uint8_t vec5[] = {0x05, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00};

	if (dt_has_node_property(dt_chosen, "ibm,architecture-vec-5", NULL))
		return;

	dt_add_property(dt_chosen, "ibm,architecture-vec-5",
			vec5, sizeof(vec5));
}

static void dt_init_misc(void)
{
	/* Check if there's a /chosen node, if not, add one */
	dt_chosen = dt_find_by_path(dt_root, "/chosen");
	if (!dt_chosen)
		dt_chosen = dt_new(dt_root, "chosen");
	assert(dt_chosen);

	/* Add IBM architecture vectors if needed */
	add_arch_vector();

	/* Add the "OPAL virtual ICS*/
	add_ics_node();

	/* Additional fixups. TODO: Move into platform */
	dt_fixups();
}

/* Called from head.S, thus no prototype. */
void main_cpu_entry(const void *fdt, u32 master_cpu);

void __noreturn main_cpu_entry(const void *fdt, u32 master_cpu)
{
	/*
	 * WARNING: At this point. the timebases have
	 * *not* been synchronized yet. Do not use any timebase
	 * related functions for timeouts etc... unless you can cope
	 * with the speed being some random core clock divider and
	 * the value jumping backward when the synchronization actually
	 * happens (in chiptod_init() below).
	 *
	 * Also the current cpu_thread() struct is not initialized
	 * either so we need to clear it out first thing first (without
	 * putting any other useful info in there jus yet) otherwise
	 * printf an locks are going to play funny games with "con_suspend"
	 */
	pre_init_boot_cpu();

	/*
	 * Before first printk, ensure console buffer is clear or
	 * reading tools might think it has wrapped
	 */
	clear_console();

	printf("SkiBoot %s starting...\n", gitid);
	printf("initial console log level: memory %d, driver %d\n",
	       (debug_descriptor.console_log_levels >> 4),
	       (debug_descriptor.console_log_levels & 0x0f));
	prlog(PR_TRACE, "You will not see this\n");

	/* Initialize boot cpu's cpu_thread struct */
	init_boot_cpu();

	/* Now locks can be used */
	init_locks();

	/* Create the OPAL call table early on, entries can be overridden
	 * later on (FSP console code for example)
	 */
	opal_table_init();

	/*
	 * If we are coming in with a flat device-tree, we expand it
	 * now. Else look for HDAT and create a device-tree from them
	 *
	 * Hack alert: When entering via the OPAL entry point, fdt
	 * is set to -1, we record that and pass it to parse_hdat
	 */
	if (fdt == (void *)-1ul)
		parse_hdat(true, master_cpu);
	else if (fdt == NULL)
		parse_hdat(false, master_cpu);
	else {
		dt_expand(fdt);
	}

	/*
	 * From there, we follow a fairly strict initialization order.
	 *
	 * First we need to build up our chip data structures and initialize
	 * XSCOM which will be needed for a number of susbequent things.
	 *
	 * We want XSCOM available as early as the platform probe in case the
	 * probe requires some HW accesses.
	 *
	 * We also initialize the FSI master at that point in case we need
	 * to access chips via that path early on.
	 */
	init_chips();
	xscom_init();
	mfsi_init();

	/*
	 * Put various bits & pieces in device-tree that might not
	 * already be there such as the /chosen node if not there yet,
	 * the ICS node, etc... This can potentially use XSCOM
	 */
	dt_init_misc();

	/*
	 * Initialize LPC (P8 only) so we can get to UART, BMC and
	 * other system controller. This is done before probe_platform
	 * so that the platform probing code can access an external
	 * BMC if needed.
	 */
	lpc_init();

	/*
	 * Now, we init our memory map from the device-tree, and immediately
	 * reserve areas which we know might contain data coming from
	 * HostBoot. We need to do these things before we start doing
	 * allocations outside of our heap, such as chip local allocs,
	 * otherwise we might clobber those data.
	 */
	mem_region_init();

	/* Reserve HOMER and OCC area */
	homer_init();

	/* Initialize host services. */
	hservices_init();

	/* Add the /opal node to the device-tree */
	add_opal_node();

	/*
	 * We probe the platform now. This means the platform probe gets
	 * the opportunity to reserve additional areas of memory if needed.
	 *
	 * Note: Timebases still not synchronized.
	 */
	probe_platform();

	/* Initialize the rest of the cpu thread structs */
	init_all_cpus();

	/* Allocate our split trace buffers now. Depends add_opal_node() */
	init_trace_buffers();

	/* Get the ICPs and make sure they are in a sane state */
	init_interrupts();

	/* Grab centaurs from device-tree if present (only on FSP-less) */
	centaur_init();

	/* Initialize PSI (depends on probe_platform being called) */
	psi_init();

	/* Call in secondary CPUs */
	cpu_bringup();

	/*
	 * Sycnhronize time bases. Thi resets all the TB values to a small
	 * value (so they appear to go backward at this point), and synchronize
	 * all core timebases to the global ChipTOD network
	 */
	chiptod_init(master_cpu);

	/*
	 * We have initialized the basic HW, we can now call into the
	 * platform to perform subsequent inits, such as establishing
	 * communication with the FSP or starting IPMI.
	 */
	if (platform.init)
		platform.init();

	/* Setup dummy console nodes if it's enabled */
	if (dummy_console_enabled())
		dummy_console_add_nodes();

	/* Init SLW related stuff, including fastsleep */
	slw_init();

	op_display(OP_LOG, OP_MOD_INIT, 0x0002);

	/* Read in NVRAM and set it up */
	nvram_init();

	/* NX init */
	nx_init();

	/* Initialize the opal messaging */
	opal_init_msg();

	/* Probe IO hubs */
	probe_p5ioc2();
	probe_p7ioc();

	/* Probe PHB3 on P8 */
	probe_phb3();

	/* Initialize PCI */
	pci_init_slots();

	/*
	 * These last few things must be done as late as possible
	 * because they rely on various other things having been setup,
	 * for example, add_opal_interrupts() will add all the interrupt
	 * sources that are going to the firmware. We can't add a new one
	 * after that call. Similarily, the mem_region calls will construct
	 * the reserve maps in the DT so we shouldn't affect the memory
	 * regions after that
	 */

	/* Add the list of interrupts going to OPAL */
	add_opal_interrupts();

	/* Now release parts of memory nodes we haven't used ourselves... */
	mem_region_release_unused();

	/* ... and add remaining reservations to the DT */
	mem_region_add_dt_reserved();

	load_and_boot_kernel(false);
}

void __noreturn __secondary_cpu_entry(void)
{
	struct cpu_thread *cpu = this_cpu();

	/* Secondary CPU called in */
	cpu_callin(cpu);

	/* Wait for work to do */
	while(true) {
		int i;

		/* Process pending jobs on this processor */
		cpu_process_jobs();

		/* Relax a bit to give the simulator some breathing space */
		i = 1000;
		while (--i)
			cpu_relax();
	}
}

/* Called from head.S, thus no prototype. */
void secondary_cpu_entry(void);

void __noreturn secondary_cpu_entry(void)
{
	struct cpu_thread *cpu = this_cpu();

	prlog(PR_DEBUG, "INIT: CPU PIR 0x%04x called in\n", cpu->pir);

	__secondary_cpu_entry();
}

