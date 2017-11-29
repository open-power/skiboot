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
#include <cpu.h>
#include <fsp.h>
#include <psi.h>
#include <opal.h>
#include <xscom.h>
#include <interrupts.h>
#include <cec.h>
#include <timebase.h>
#include <pci.h>
#include <chip.h>
#include <chiptod.h>
#include <ipmi.h>
#include <direct-controls.h>

/* Flag tested by the OPAL entry code */
uint8_t reboot_in_progress;
static volatile bool fast_boot_release;
static struct lock reset_lock = LOCK_UNLOCKED;

static bool cpu_state_wait_all_others(enum cpu_thread_state state,
					unsigned long timeout_tb)
{
	struct cpu_thread *cpu;
	unsigned long end = mftb() + timeout_tb;

	sync();
	for_each_ungarded_cpu(cpu) {
		if (cpu == this_cpu())
			continue;

		if (cpu->state != state) {
			smt_lowest();
			while (cpu->state != state) {
				barrier();

				if (timeout_tb && (tb_compare(mftb(), end) == TB_AAFTERB)) {
					smt_medium();
					return false;
				}
			}
			smt_medium();
		}
	}
	sync();

	return true;
}

extern void *fdt;
extern struct lock capi_lock;

static const char *fast_reboot_disabled = NULL;
static struct lock fast_reboot_disabled_lock = LOCK_UNLOCKED;

void disable_fast_reboot(const char *reason)
{
	lock(&fast_reboot_disabled_lock);
	fast_reboot_disabled = reason;
	unlock(&fast_reboot_disabled_lock);
}

void fast_reboot(void)
{
	struct cpu_thread *cpu;
	static int fast_reboot_count = 0;

	if (!chip_quirk(QUIRK_MAMBO_CALLOUTS) &&
			proc_gen != proc_gen_p8) {
		prlog(PR_DEBUG,
		      "RESET: Fast reboot not available on this CPU\n");
		return;
	}
	if (chip_quirk(QUIRK_NO_DIRECT_CTL)) {
		prlog(PR_DEBUG,
		      "RESET: Fast reboot disabled by quirk\n");
		return;
	}

	lock(&fast_reboot_disabled_lock);
	if (fast_reboot_disabled) {
		prlog(PR_DEBUG, "RESET: Fast reboot disabled because %s\n",
		      fast_reboot_disabled);
		unlock(&fast_reboot_disabled_lock);
		return;
	}
	unlock(&fast_reboot_disabled_lock);

	prlog(PR_NOTICE, "RESET: Initiating fast reboot %d...\n", ++fast_reboot_count);
	free(fdt);

	/* XXX We need a way to ensure that no other CPU is in skiboot
	 * holding locks (via the OPAL APIs) and if they are, we need
	 * for them to get out. Hopefully that isn't happening, but...
	 *
	 * To fix this properly, we want to keep track of OPAL entry/exit
	 * on all CPUs.
	 */
	reboot_in_progress = 1;
	time_wait_ms(200);

	/* Lock so the new guys coming don't reset us */
	lock(&reset_lock);

	fast_boot_release = false;
	sync();

	/* Put everybody in stop except myself */
	if (sreset_all_prepare())
		return;

	/* Now everyone else is stopped */
	unlock(&reset_lock);

	/*
	 * There is no point clearing special wakeup due to failure after this
	 * point, because we will be going to full IPL. Less cleanup work means
	 * less opportunity to fail.
	 */

	for_each_ungarded_cpu(cpu) {
		/* Also make sure that saved_r1 is 0 ! That's what will
		 * make our reset vector jump to fast_reboot_entry
		 */
		cpu->save_r1 = 0;
	}

	/* Restore skiboot vectors  */
	copy_exception_vectors();
	setup_reset_vector();

	/* Send everyone else to 0x100 */
	if (sreset_all_others() != OPAL_SUCCESS)
		return;

	/* Ensure all the sresets get through */
	if (!cpu_state_wait_all_others(cpu_state_present, msecs_to_tb(100)))
		return;

	prlog(PR_DEBUG, "RESET: Releasing special wakeups...\n");
	sreset_all_finish();

	asm volatile("ba	0x100\n\t" : : : "memory");
	for (;;)
		;
}

static void cleanup_cpu_state(void)
{
	struct cpu_thread *cpu = this_cpu();

	/* Per core cleanup */
	if (cpu_is_thread0(cpu)) {
		/* Shared SPRs whacked back to normal */

		/* XXX Update the SLW copies ! Also dbl check HIDs etc... */
		init_shared_sprs();

		/* If somebody was in fast_sleep, we may have a workaround
		 * to undo
		 */
		if (cpu->in_fast_sleep) {
			prlog(PR_DEBUG, "RESET: CPU 0x%04x in fast sleep"
			      " undoing workarounds...\n", cpu->pir);
			fast_sleep_exit();
		}

		/* And we might have lost TB sync */
		chiptod_wakeup_resync();

		/* The TLB surely contains garbage */
		cleanup_local_tlb();
	}

	/* Per-thread additional cleanup */
	init_replicated_sprs();

	// XXX Cleanup SLW, check HIDs ...
}

void __noreturn enter_nap(void);

static void check_split_core(void)
{
	struct cpu_thread *cpu;
	u64 mask, hid0;

        hid0 = mfspr(SPR_HID0);
	mask = SPR_HID0_POWER8_4LPARMODE | SPR_HID0_POWER8_2LPARMODE;

	if ((hid0 & mask) == 0)
		return;

	prlog(PR_INFO, "RESET: CPU 0x%04x is split !\n", this_cpu()->pir);

	/* If it's a secondary thread, just send it to nap */
	if (this_cpu()->pir & 7) {
		/* Prepare to be woken up */
		icp_prep_for_pm();
		/* Setup LPCR to wakeup on external interrupts only */
		mtspr(SPR_LPCR, ((mfspr(SPR_LPCR) & ~SPR_LPCR_P8_PECE) |
				 SPR_LPCR_P8_PECE2));
		/* Go to nap (doesn't return) */
		enter_nap();
	}

	prlog(PR_INFO, "RESET: Primary, unsplitting... \n");

	/* Trigger unsplit operation and update SLW image */
	hid0 &= ~SPR_HID0_POWER8_DYNLPARDIS;
	set_hid0(hid0);
	opal_slw_set_reg(this_cpu()->pir, SPR_HID0, hid0);

	/* Wait for unsplit */
	while (mfspr(SPR_HID0) & mask)
		cpu_relax();

	/* Now the guys are sleeping, wake'em up. They will come back
	 * via reset and continue the fast reboot process normally.
	 * No need to wait.
	 */
	prlog(PR_INFO, "RESET: Waking unsplit secondaries... \n");

	for_each_cpu(cpu) {
		if (!cpu_is_sibling(cpu, this_cpu()) || (cpu == this_cpu()))
			continue;
		icp_kick_cpu(cpu);
	}
}


/* Entry from asm after a fast reset */
void __noreturn fast_reboot_entry(void);

void __noreturn fast_reboot_entry(void)
{
	prlog(PR_DEBUG, "RESET: CPU 0x%04x reset in\n", this_cpu()->pir);

	/* We reset our ICP first ! Otherwise we might get stray interrupts
	 * when unsplitting
	 */
	reset_cpu_icp();

	/* If we are split, we need to unsplit. Since that can send us
	 * to NAP, which will come back via reset, we do it now
	 */
	check_split_core();

	sync();
	this_cpu()->state = cpu_state_present;
	sync();

	/* Are we the original boot CPU ? If not, we spin waiting
	 * for a relase signal from CPU 1, then we clean ourselves
	 * up and go processing jobs.
	 */
	if (this_cpu() != boot_cpu) {
		if (!fast_boot_release) {
			smt_lowest();
			while (!fast_boot_release)
				barrier();
			smt_medium();
		}
		sync();
		cleanup_cpu_state();
		__secondary_cpu_entry();
	}

	prlog(PR_INFO, "RESET: Boot CPU waiting for everybody...\n");

	/* We are the original boot CPU, wait for secondaries to
	 * be captured.
	 */
	cpu_state_wait_all_others(cpu_state_present, 0);

	prlog(PR_INFO, "RESET: Releasing secondaries...\n");

	/* Release everybody */
	sync();
	fast_boot_release = true;

	/* Wait for them to respond */
	cpu_state_wait_all_others(cpu_state_active, 0);

	sync();

	prlog(PR_INFO, "RESET: All done, cleaning up...\n");

	/* Clear release flag for next time */
	fast_boot_release = false;
	reboot_in_progress = 0;

	/* Cleanup ourselves */
	cleanup_cpu_state();

	/* Set our state to active */
	sync();
	this_cpu()->state = cpu_state_active;
	sync();

	/* Let the CPU layer do some last minute global cleanups */
	cpu_fast_reboot_complete();

	/* We can now do NAP mode */
	cpu_set_sreset_enable(true);
	cpu_set_ipi_enable(true);

	/* Start preloading kernel and ramdisk */
	start_preload_kernel();

	/* Poke the consoles (see comments in the code there) */
	fsp_console_reset();

	/* Reset/EOI the PSI interrupt */
	psi_irq_reset();

	/* Remove all PCI devices */
	pci_reset();

	ipmi_set_fw_progress_sensor(IPMI_FW_PCI_INIT);

	/* Load and boot payload */
	load_and_boot_kernel(true);
}
