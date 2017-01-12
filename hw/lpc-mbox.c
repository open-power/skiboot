/* Copyright 2016 IBM Corp.
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

#define pr_fmt(fmt) "LPC-MBOX: " fmt

#include <skiboot.h>
#include <lpc.h>
#include <console.h>
#include <opal.h>
#include <device.h>
#include <interrupts.h>
#include <processor.h>
#include <errorlog.h>
#include <trace.h>
#include <timebase.h>
#include <timer.h>
#include <cpu.h>
#include <chip.h>
#include <io.h>

#include <lpc-mbox.h>

#define MBOX_FLAG_REG 0x0f
#define MBOX_STATUS_0 0x10
#define   MBOX_STATUS_BIT15 (1 << 7)
#define MBOX_STATUS_1 0x11
#define MBOX_BMC_CTRL 0x12
#define   MBOX_CTRL_INT_STATUS (1 << 7)
#define   MBOX_CTRL_INT_MASK (1 << 1)
#define   MBOX_CTRL_INT_SEND (1 << 0)
#define MBOX_HOST_CTRL 0x13
#define MBOX_BMC_INT_EN_0 0x14
#define MBOX_BMC_INT_EN_1 0x15
#define MBOX_HOST_INT_EN_0 0x16
#define MBOX_HOST_INT_EN_1 0x17

#define MBOX_MAX_QUEUE_LEN 5

#define BMC_RESET 1
#define BMC_COMPLETE 2

struct mbox {
	uint32_t base;
	int queue_len;
	bool irq_ok;
	uint8_t seq;
	struct lock lock;
	struct timer poller;
	struct list_head msgq;
};

static struct mbox mbox;
static struct bmc_mbox_msg msg_mem[MBOX_MAX_QUEUE_LEN];

/*
 * MBOX accesses
 */

static void bmc_mbox_outb(uint8_t val, uint8_t reg)
{
	lpc_outb(val, mbox.base + reg);
}

static uint8_t bmc_mbox_inb(uint8_t reg)
{
	return lpc_inb(mbox.base + reg);
}

static void bmc_mbox_recv_message(struct bmc_mbox_msg *msg)
{
	int i;

	msg->response = bmc_mbox_inb(13);
	msg->seq = bmc_mbox_inb(1);
	prlog(PR_DEBUG, "Receving message resp %d seq: %d\n",
			msg->response, msg->seq);
	for (i = 0; i < BMC_MBOX_DATA_BYTES; i++) {
		msg->data[i] = bmc_mbox_inb(i + 2);
		prlog(PR_TRACE, "Read byte %d val 0x%02x\n", i, msg->data[i]);
	}
	prlog(PR_DEBUG, "Done\n");
}

/* This needs work, don't write the data bytes that aren't needed */
static void bmc_mbox_send_message(struct bmc_mbox_msg *msg)
{
	int i;

	if (!lpc_ok())
		/* We're going to have to handle this better */
		prlog(PR_ERR, "LPC isn't ok\n");
	prlog(PR_DEBUG, "Sending command %d seq %d\n", msg->command, msg->seq);
	bmc_mbox_outb(msg->command, 0);
	bmc_mbox_outb(msg->seq, 1);
	for (i = 0; i < BMC_MBOX_DATA_BYTES; i++) {
		prlog(PR_TRACE, "Sending byte %d val %d\n", i + 2, msg->data[i]);
		bmc_mbox_outb(msg->data[i], i + 2);
	}

	/* Ping */
	prlog(PR_DEBUG, "Sending BMC interrupt\n");
	bmc_mbox_outb(MBOX_CTRL_INT_SEND, MBOX_HOST_CTRL);
}

int bmc_mbox_enqueue(struct bmc_mbox_msg *msg)
{
	int rc = 0;
	lock(&mbox.lock);
	if (mbox.queue_len == MBOX_MAX_QUEUE_LEN) {
		rc = -1;
		goto out;
	}

	msg->seq = ++mbox.seq;
	memcpy(&msg_mem[mbox.queue_len], msg, sizeof(*msg));
	list_add_tail(&mbox.msgq, &msg_mem[mbox.queue_len].link);
	mbox.queue_len++;
	/*
	 * If there is already a message in the queue it means we're
	 * waiting for a response and we'll send this one when we get the
	 * response
	 */
	if (mbox.queue_len == 1)
		bmc_mbox_send_message(msg);

	schedule_timer(&mbox.poller,
		       mbox.irq_ok ? TIMER_POLL : msecs_to_tb(MBOX_DEFAULT_POLL_MS));
out:
	unlock(&mbox.lock);
	return rc;
}

static void mbox_poll(struct timer *t __unused, void *data __unused,
		uint64_t now __unused)
{
	struct bmc_mbox_msg *msg;

	/* This is a 'registered' the message you just sent me */
	if (bmc_mbox_inb(MBOX_HOST_CTRL) & MBOX_CTRL_INT_STATUS) {
		prlog(PR_INSANE, "IRQ was for me\n");
		/* W1C on that reg */
		bmc_mbox_outb(MBOX_CTRL_INT_STATUS, MBOX_HOST_CTRL);

		prlog(PR_INSANE, "Got a regular interrupt\n");
		/*
		 * Better implementations could allow for having
		 * mulitiple outstanding messages to the BMC, in that
		 * case the responded message wouldn't necessarily be
		 * list_top()
		 */
		/*
		 * This should be safe lockless
		 */
		prlog(PR_INSANE, "Looking up in list\n");
		msg = list_top(&mbox.msgq, struct bmc_mbox_msg, link);
		prlog(PR_INSANE, "Calling recv_message on %p\n", msg);
		bmc_mbox_recv_message(msg);
		prlog(PR_INSANE, "Calling callback %p\n", msg->callback);
		msg->callback(msg);
		prlog(PR_INSANE, "Callback returned\n");

		/* Yeah we'll need locks here */
		lock(&mbox.lock);
		msg = list_top(&mbox.msgq, struct bmc_mbox_msg, link);
		list_del(&msg->link);
		mbox.queue_len--;
		if (mbox.queue_len) {
			msg = list_top(&mbox.msgq, struct bmc_mbox_msg, link);
			bmc_mbox_send_message(msg);
		}
		unlock(&mbox.lock);
	}

	/* This is to indicate that the BMC has information to tell us */
	if (bmc_mbox_inb(MBOX_STATUS_1) & MBOX_STATUS_BIT15) {
		uint8_t action;

		prlog(PR_INSANE, "IRQ was for me\n");
		/* W1C on that reg */
		bmc_mbox_outb(MBOX_STATUS_BIT15, MBOX_STATUS_1);

		action = bmc_mbox_inb(MBOX_FLAG_REG);
		prlog(PR_INSANE, "Got a status register interrupt with action 0x%02x\n",
				action);

		if (action & BMC_RESET) {
			/* Freak */
			prlog(PR_WARNING, "BMC reset detected\n");
			action &= ~BMC_RESET;
		}

		if (action & BMC_COMPLETE) {
			/* There is going to need to be a way to tell to tell
			 * message owner this happened...
			 * a) Call callback twice with flags
			 * b) Two callbacks
			 * c) Some elaborate set of flags that the message owner
			 *    can specify what they want...
			 * d) Always call callback now (rather terrible)
			 */
			action &= ~BMC_COMPLETE;
		}

		if (action)
			prlog(PR_ERR, "Got a status bit set that don't know about: 0x%02x\n",
					action);
	}

	schedule_timer(&mbox.poller,
		       mbox.irq_ok ? TIMER_POLL : msecs_to_tb(MBOX_DEFAULT_POLL_MS));
}

static void mbox_irq(uint32_t chip_id __unused, uint32_t irq_mask __unused)
{
	mbox.irq_ok = true;
	mbox_poll(NULL, NULL, 0);
}

static struct lpc_client mbox_lpc_client = {
	.interrupt = mbox_irq,
};

static bool mbox_init_hw(void)
{
	/*
	 * Turns out there isn't anything to do.
	 * It might be a good idea to santise the registers though.
	 * TODO
	 */
	return true;
}

void mbox_init(void)
{
	const struct dt_property *prop;
	struct dt_node *n;
	uint32_t irq, chip_id;

	prlog(PR_DEBUG, "Attempting mbox init\n");
	n = dt_find_compatible_node(dt_root, NULL, "mbox");
	if (!n) {
		prlog(PR_ERR, "No device tree entry\n");
		return;
	}

	/* Read the interrupts property if any */
	irq = dt_prop_get_u32_def(n, "interrupts", 0);
	if (!irq) {
		prlog(PR_ERR, "No interrupts property\n");
		return;
	}

	if (!lpc_present()) {
		prlog(PR_ERR, "LPC not present\n");
		return;
	}

	/* Get IO base */
	prop = dt_find_property(n, "reg");
	if (!prop) {
		prlog(PR_ERR, "Can't find reg property\n");
		return;
	}
	if (dt_property_get_cell(prop, 0) != OPAL_LPC_IO) {
		prlog(PR_ERR, "Only supports IO addresses\n");
		return;
	}
	mbox.base = dt_property_get_cell(prop, 1);

	if (!mbox_init_hw()) {
		prlog(PR_DEBUG, "Couldn't init HW\n");
		return;
	}

	mbox.queue_len = 0;
	list_head_init(&mbox.msgq);
	init_lock(&mbox.lock);

	init_timer(&mbox.poller, mbox_poll, NULL);

	chip_id = dt_get_chip_id(n);
	mbox_lpc_client.interrupts = LPC_IRQ(irq);
	lpc_register_client(chip_id, &mbox_lpc_client);
	prlog(PR_DEBUG, "Using %d chipid and %d IRQ at 0x%08x\n", chip_id, irq, mbox.base);
}


