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
#include <opal.h>
#include <stack.h>
#include <lock.h>
#include <fsp.h>
#include <cpu.h>
#include <interrupts.h>
#include <op-panel.h>
#include <device.h>
#include <console.h>
#include <trace.h>
#include <timebase.h>
#include <affinity.h>
#include <opal-msg.h>

/* Pending events to signal via opal_poll_events */
uint64_t opal_pending_events;

/* OPAL dispatch table defined in head.S */
extern uint64_t opal_branch_table[];

/* Number of args expected for each call. */
static u8 opal_num_args[OPAL_LAST+1];

/* OPAL anchor node */
struct dt_node *opal_node;

extern uint32_t attn_trigger;
extern uint32_t hir_trigger;

void opal_table_init(void)
{
	struct opal_table_entry *s = __opal_table_start;
	struct opal_table_entry *e = __opal_table_end;

	printf("OPAL table: %p .. %p, branch table: %p\n",
	       s, e, opal_branch_table);
	while(s < e) {
		uint64_t *func = s->func;
		opal_branch_table[s->token] = *func;
		opal_num_args[s->token] = s->nargs;
		s++;
	}
}

/* Called from head.S, thus no prototype */
long opal_bad_token(uint64_t token);

long opal_bad_token(uint64_t token)
{
	prerror("OPAL: Called with bad token %lld !\n", token);

	return OPAL_PARAMETER;
}

/* Called from head.S, thus no prototype */
void opal_trace_entry(struct stack_frame *eframe);

/* FIXME: Do this in asm */ 
void opal_trace_entry(struct stack_frame *eframe)
{
	union trace t;
	unsigned nargs;

	if (this_cpu()->pir != mfspr(SPR_PIR)) {
		printf("CPU MISMATCH ! PIR=%04lx cpu @%p -> pir=%04x\n",
		       mfspr(SPR_PIR), this_cpu(), this_cpu()->pir);
		abort();
	}
	if (eframe->gpr[0] > OPAL_LAST)
		nargs = 0;
	else
		nargs = opal_num_args[eframe->gpr[0]];

	t.opal.token = eframe->gpr[0];
	t.opal.lr = eframe->lr;
	t.opal.sp = eframe->gpr[1];
	memcpy(t.opal.r3_to_11, &eframe->gpr[3], nargs*sizeof(u64));

	trace_add(&t, TRACE_OPAL, offsetof(struct trace_opal, r3_to_11[nargs]));
}

void __opal_register(uint64_t token, void *func, unsigned int nargs)
{
	uint64_t *opd = func;

	assert(token <= OPAL_LAST);

	opal_branch_table[token] = *opd;
	opal_num_args[token] = nargs;
}

static void add_opal_firmware_node(void)
{
	struct dt_node *firmware = dt_new(opal_node, "firmware");

	dt_add_property_string(firmware, "compatible", "ibm,opal-firmware");
	dt_add_property_string(firmware, "name", "firmware");
	dt_add_property_string(firmware, "git-id", gitid);
}

void add_opal_node(void)
{
	uint64_t base, entry, size;
	extern uint32_t opal_entry;

	/* XXX TODO: Reorg this. We should create the base OPAL
	 * node early on, and have the various sub modules populate
	 * their own entries (console etc...)
	 *
	 * The logic of which console backend to use should be
	 * extracted
	 */

	entry = (uint64_t)&opal_entry;
	base = SKIBOOT_BASE;
	size = (CPU_STACKS_BASE +
		(cpu_max_pir + 1) * STACK_SIZE) - SKIBOOT_BASE;

	opal_node = dt_new(dt_root, "ibm,opal");
	dt_add_property_cells(opal_node, "#address-cells", 0);
	dt_add_property_cells(opal_node, "#size-cells", 0);
	dt_add_property_strings(opal_node, "compatible", "ibm,opal-v2",
				"ibm,opal-v3");
	dt_add_property_cells(opal_node, "opal-msg-async-num", OPAL_MAX_ASYNC_COMP);
	dt_add_property_cells(opal_node, "opal-msg-size", sizeof(struct opal_msg));
	dt_add_property_u64(opal_node, "opal-base-address", base);
	dt_add_property_u64(opal_node, "opal-entry-address", entry);
	dt_add_property_u64(opal_node, "opal-runtime-size", size);

	add_opal_firmware_node();
	add_associativity_ref_point();
	memcons_add_properties();
	add_cpu_idle_state_properties();
}

void opal_update_pending_evt(uint64_t evt_mask, uint64_t evt_values)
{
	static struct lock evt_lock = LOCK_UNLOCKED;
	uint64_t new_evts;

	/* XXX FIXME: Use atomics instead ??? Or caller locks (con_lock ?) */
	lock(&evt_lock);
	new_evts = (opal_pending_events & ~evt_mask) | evt_values;
#ifdef OPAL_TRACE_EVT_CHG
	printf("OPAL: Evt change: 0x%016llx -> 0x%016llx\n",
	       opal_pending_events, new_evts);
#endif
	opal_pending_events = new_evts;
	unlock(&evt_lock);
}


static uint64_t opal_test_func(uint64_t arg)
{
	printf("OPAL: Test function called with arg 0x%llx\n", arg);

	return 0xfeedf00d;
}
opal_call(OPAL_TEST, opal_test_func, 1);

struct opal_poll_entry {
	struct list_node	link;
	void			(*poller)(void *data);
	void			*data;
};

static struct list_head opal_pollers = LIST_HEAD_INIT(opal_pollers);
static struct lock opal_poll_lock = LOCK_UNLOCKED;

void opal_add_poller(void (*poller)(void *data), void *data)
{
	struct opal_poll_entry *ent;

	ent = zalloc(sizeof(struct opal_poll_entry));
	assert(ent);
	ent->poller = poller;
	ent->data = data;
	lock(&opal_poll_lock);
	list_add_tail(&opal_pollers, &ent->link);
	unlock(&opal_poll_lock);
}

void opal_del_poller(void (*poller)(void *data))
{
	struct opal_poll_entry *ent;

	lock(&opal_poll_lock);
	list_for_each(&opal_pollers, ent, link) {
		if (ent->poller == poller) {
			list_del(&ent->link);
			free(ent);
			break;
		}
	}
	unlock(&opal_poll_lock);
}

bool __opal_check_poll_recursion(const char *caller)
{
	if (!lock_held_by_me(&opal_poll_lock))
		return false;
	prerror("OPAL: poller recursion caught in %s !\n", caller);
	backtrace();

	return true;
}

void __opal_run_pollers(const char *caller)
{
	struct opal_poll_entry *poll_ent;

	/* Debug path. Warn if we recursed */
	if (__opal_check_poll_recursion(caller)) {
		/* This shouldn't happen. However, if it does, we are goin
		 * to end up warning a *LOT* so let's introduce an arbitrary
		 * delay here.
		 */
		time_wait_ms_nopoll(10);
		return;
	}

	/*
	 * Only run the pollers if they aren't already running
	 * on another CPU and we aren't re-entering.
	 */
	if (try_lock(&opal_poll_lock)) {
		list_for_each(&opal_pollers, poll_ent, link)
			poll_ent->poller(poll_ent->data);
		unlock(&opal_poll_lock);
	}
}

static int64_t opal_poll_events(uint64_t *outstanding_event_mask)
{
	/* Check if we need to trigger an attn for test use */
	if (attn_trigger == 0xdeadbeef) {
		printf("Triggering attn\n");
		assert(false);
	}

	/* Test the host initiated reset */
	if (hir_trigger == 0xdeadbeef) {
		fsp_trigger_reset();
		hir_trigger = 0;
	}

	opal_run_pollers();

	if (outstanding_event_mask)
		*outstanding_event_mask = opal_pending_events;

	return OPAL_SUCCESS;
}
opal_call(OPAL_POLL_EVENTS, opal_poll_events, 1);

static int64_t opal_check_token(uint64_t token)
{
	if (token > OPAL_LAST)
		return OPAL_TOKEN_ABSENT;

	if (opal_branch_table[token])
		return OPAL_TOKEN_PRESENT;

	return OPAL_TOKEN_ABSENT;
}
opal_call(OPAL_CHECK_TOKEN, opal_check_token, 1);

struct opal_sync_entry {
	struct list_node	link;
	bool			(*notify)(void *data);
	void			*data;
};

static struct list_head opal_syncers = LIST_HEAD_INIT(opal_syncers);

void opal_add_host_sync_notifier(bool (*notify)(void *data), void *data)
{
	struct opal_sync_entry *ent;

	ent = zalloc(sizeof(struct opal_sync_entry));
	assert(ent);
	ent->notify = notify;
	ent->data = data;
	list_add_tail(&opal_syncers, &ent->link);
}

void opal_del_host_sync_notifier(bool (*notify)(void *data))
{
	struct opal_sync_entry *ent;

	list_for_each(&opal_syncers, ent, link) {
		if (ent->notify == notify) {
			list_del(&ent->link);
			free(ent);
			return;
		}
	}
}

/*
 * OPAL call to handle host kexec'ing scenario
 */
static int64_t opal_sync_host_reboot(void)
{
	struct opal_sync_entry *ent;
	bool ret = true;

	list_for_each(&opal_syncers, ent, link)
		ret &= ent->notify(ent->data);

	if (ret)
		return OPAL_SUCCESS;
	else
		return OPAL_BUSY_EVENT;
}
opal_call(OPAL_SYNC_HOST_REBOOT, opal_sync_host_reboot, 0);
