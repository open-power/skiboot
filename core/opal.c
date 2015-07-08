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
#include <timer.h>

/* Pending events to signal via opal_poll_events */
uint64_t opal_pending_events;

/* OPAL dispatch table defined in head.S */
extern uint64_t opal_branch_table[];

/* Number of args expected for each call. */
static u8 opal_num_args[OPAL_LAST+1];

/* OPAL anchor node */
struct dt_node *opal_node;

/* mask of dynamic vs fixed events; opal_allocate_dynamic_event will
 * only allocate from this range */
static const uint64_t opal_dynamic_events_mask = 0xffffffff00000000ul;
static uint64_t opal_dynamic_events;

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
	uint64_t sym_start = (uint64_t)__sym_map_start;
	uint64_t sym_size = (uint64_t)__sym_map_end - sym_start;
	dt_add_property_string(firmware, "compatible", "ibm,opal-firmware");
	dt_add_property_string(firmware, "name", "firmware");
	dt_add_property_string(firmware, "version", version);
	dt_add_property_cells(firmware, "symbol-map",
			      hi32(sym_start), lo32(sym_start),
			      hi32(sym_size), lo32(sym_size));
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
		(uint64_t)(cpu_max_pir + 1) * STACK_SIZE) - SKIBOOT_BASE;

	if (!opal_node) {
		opal_node = dt_new(dt_root, "ibm,opal");
		assert(opal_node);
	}

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
}

static struct lock evt_lock = LOCK_UNLOCKED;

void opal_update_pending_evt(uint64_t evt_mask, uint64_t evt_values)
{
	uint64_t new_evts;

	/* XXX FIXME: Use atomics instead ??? Or caller locks (con_lock ?) */
	lock(&evt_lock);
	new_evts = (opal_pending_events & ~evt_mask) | evt_values;
	if (opal_pending_events != new_evts) {
		uint64_t tok;

#ifdef OPAL_TRACE_EVT_CHG
		printf("OPAL: Evt change: 0x%016llx -> 0x%016llx\n",
		       opal_pending_events, new_evts);
#endif
		/*
		 * If an event gets *set* while we are in a different call chain
		 * than opal_handle_interrupt() or opal_handle_hmi(), then we
		 * artificially generate an interrupt (OCC interrupt specifically)
		 * to ensure that Linux properly broadcast the event change internally
		 */
		if ((new_evts & ~opal_pending_events) != 0) {
			tok = this_cpu()->current_token;
			if (tok != OPAL_HANDLE_INTERRUPT && tok != OPAL_HANDLE_HMI)
				occ_send_dummy_interrupt();
		}
		opal_pending_events = new_evts;
	}
	unlock(&evt_lock);
}

uint64_t opal_dynamic_event_alloc(void)
{
	uint64_t new_event;
	int n;

	lock(&evt_lock);

	/* Create the event mask. This set-bit will be within the event mask
	 * iff there are free events, or out of the mask if there are no free
	 * events. If opal_dynamic_events is all ones (ie, all events are
	 * dynamic, and allocated), then ilog2 will return -1, and we'll have a
	 * zero mask.
	 */
	n = ilog2(~opal_dynamic_events);
	new_event = 1ull << n;

	/* Ensure we're still within the allocatable dynamic events range */
	if (new_event & opal_dynamic_events_mask)
		opal_dynamic_events |= new_event;
	else
		new_event = 0;

	unlock(&evt_lock);
	return new_event;
}

void opal_dynamic_event_free(uint64_t event)
{
	lock(&evt_lock);
	opal_dynamic_events &= ~event;
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

	/* XXX This is currently unused. To solve various "interesting"
	 * locking issues, the pollers are run locklessly, so if we were
	 * to free them, we would have to be careful, using something
	 * akin to RCU to synchronize with other OPAL entries. For now
	 * if anybody uses it, print a warning and leak the entry, don't
	 * free it.
	 */
	prlog(PR_ALERT, "WARNING: Unsupported opal_del_poller."
	      " Interesting locking issues, don't call this.\n");

	lock(&opal_poll_lock);
	list_for_each(&opal_pollers, ent, link) {
		if (ent->poller == poller) {
			list_del(&ent->link);
			/* free(ent); */
			break;
		}
	}
	unlock(&opal_poll_lock);
}

void opal_run_pollers(void)
{
	struct opal_poll_entry *poll_ent;
	static int pollers_with_lock_warnings = 0;

	/* Don't re-enter on this CPU */
	if (this_cpu()->in_poller) {
		prlog(PR_ERR, "OPAL: Poller recursion detected.\n");
		backtrace();
		return;
	}
	this_cpu()->in_poller = true;

	if (this_cpu()->lock_depth && pollers_with_lock_warnings < 64) {
		prlog(PR_ERR, "Running pollers with lock held !\n");
		backtrace();
		pollers_with_lock_warnings++;
		if (pollers_with_lock_warnings == 64)
			prlog(PR_ERR, "opal_run_pollers with lock run 64 "
			      "times, disabling warning.\n");
	}

	/* We run the timers first */
	check_timers(false);

	/* The pollers are run lokelessly, see comment in opal_del_poller */
	list_for_each(&opal_pollers, poll_ent, link)
		poll_ent->poller(poll_ent->data);

	/* Disable poller flag */
	this_cpu()->in_poller = false;

	/* On debug builds, print max stack usage */
	check_stacks();
}

static int64_t opal_poll_events(uint64_t *outstanding_event_mask)
{
	/* Check if we need to trigger an attn for test use */
	if (attn_trigger == 0xdeadbeef) {
		prlog(PR_EMERG, "Triggering attn\n");
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
