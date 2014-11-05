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
#include <lpc.h>
#include <lock.h>
#include <device.h>
#include <timebase.h>
#include <ipmi.h>
#include <bt.h>

/* BT registers */
#define BT_CTRL			0
#define   BT_CTRL_B_BUSY		0x80
#define   BT_CTRL_H_BUSY		0x40
#define   BT_CTRL_OEM0			0x20
#define   BT_CTRL_SMS_ATN		0x10
#define   BT_CTRL_B2H_ATN		0x08
#define   BT_CTRL_H2B_ATN		0x04
#define   BT_CTRL_CLR_RD_PTR		0x02
#define   BT_CTRL_CLR_WR_PTR		0x01
#define BT_HOST2BMC		1
#define BT_INTMASK		2
#define   BT_INTMASK_B2H_IRQEN		0x01
#define   BT_INTMASK_B2H_IRQ		0x02
#define   BT_INTMASK_BMC_HWRST		0x80

/*
 * Minimum size of an IPMI request/response including
 * mandatory headers.
 */
#define BT_MIN_REQ_LEN 3
#define BT_MIN_RESP_LEN 4

/*
 * How long (in uS) to poll for new ipmi data.
 */
#define POLL_TIMEOUT 10000

/*
 * Maximum number of outstanding messages to allow in the queue.
 */
#define BT_MAX_QUEUE_LEN 5

/*
 * How long (in TB ticks) before a message is timed out.
 */
#define BT_MSG_TIMEOUT (secs_to_tb(3))

#define BT_QUEUE_DEBUG 0

enum bt_states {
	BT_STATE_IDLE = 0,
	BT_STATE_RESP_WAIT,
	BT_STATE_B_BUSY,
};

const char *state_str[] = {
	"BT_STATE_IDLE",
	"BT_STATE_RESP_WAIT",
	"BT_STATE_B_BUSY",
};

struct bt_msg {
	struct list_node link;
	unsigned long tb;
	uint8_t seq;
	struct ipmi_msg ipmi_msg;
};

struct bt {
	uint32_t base_addr;
	enum bt_states state;
	struct lock bt_lock;
	struct lock msgq_lock;
	struct list_head msgq;
	int queue_len;
};
static struct bt bt;

static int ipmi_seq;

static inline uint8_t bt_inb(uint32_t reg)
{
	return lpc_inb(bt.base_addr + reg);
}

static inline void bt_outb(uint8_t data, uint32_t reg)
{
	lpc_outb(data, bt.base_addr + reg);
}

static inline void bt_set_h_busy(bool value)
{
	uint8_t rval;

	rval = bt_inb(BT_CTRL);
	if (value != !!(rval & BT_CTRL_H_BUSY))
		bt_outb(BT_CTRL_H_BUSY, BT_CTRL);
}

static inline bool bt_idle(void)
{
	return !(bt_inb(BT_CTRL) & (BT_CTRL_B_BUSY | BT_CTRL_H2B_ATN));
}

static inline void bt_set_state(enum bt_states next_state)
{
	bt.state = next_state;
}

static void bt_msg_del(struct bt_msg *bt_msg)
{
	list_del(&bt_msg->link);
	bt.queue_len--;
	ipmi_cmd_done(bt_msg->ipmi_msg.cmd, bt_msg->ipmi_msg.netfn + 1,
		      IPMI_TIMEOUT_ERR, &bt_msg->ipmi_msg);
}

static void bt_reset_interface(void)
{
	bt_outb(BT_INTMASK_BMC_HWRST, BT_INTMASK);
	bt_set_state(BT_STATE_B_BUSY);
}

static void bt_init_interface(void)
{
	/* Clear interrupt condition & enable irq */
	bt_outb(BT_INTMASK_B2H_IRQ | BT_INTMASK_B2H_IRQEN, BT_INTMASK);

	/* Take care of a stable H_BUSY if any */
	bt_set_h_busy(false);

	bt_set_state(BT_STATE_B_BUSY);
}

static bool bt_try_send_msg(void)
{
	int i;
	struct bt_msg *bt_msg;
	struct ipmi_msg *ipmi_msg;

	lock(&bt.msgq_lock);
	bt_msg = list_top(&bt.msgq, struct bt_msg, link);
	if (!bt_msg) {
		unlock(&bt.msgq_lock);
		return true;
	}

	ipmi_msg = &bt_msg->ipmi_msg;

	if (!bt_idle()) {
		prerror("BT: Interface in an unexpected state, attempting reset\n");
		bt_reset_interface();
		unlock(&bt.msgq_lock);
		return false;
	}

	/* Send the message */
	bt_outb(BT_CTRL_CLR_WR_PTR, BT_CTRL);

	/* Byte 1 - Length */
	bt_outb(ipmi_msg->req_size + BT_MIN_REQ_LEN, BT_HOST2BMC);

	/* Byte 2 - NetFn/LUN */
	bt_outb(ipmi_msg->netfn, BT_HOST2BMC);

	/* Byte 3 - Seq */
	bt_outb(bt_msg->seq, BT_HOST2BMC);

	/* Byte 4 - Cmd */
	bt_outb(ipmi_msg->cmd, BT_HOST2BMC);

	/* Byte 5:N - Data */
	for (i = 0; i < ipmi_msg->req_size; i++)
		bt_outb(ipmi_msg->data[i], BT_HOST2BMC);

	bt_outb(BT_CTRL_H2B_ATN, BT_CTRL);
	bt_set_state(BT_STATE_RESP_WAIT);
	unlock(&bt.msgq_lock);

	return true;
}

static void bt_flush_msg(void)
{
	bt_outb(BT_CTRL_B2H_ATN | BT_CTRL_CLR_RD_PTR, BT_CTRL);
	bt_set_h_busy(false);
}

static bool bt_get_resp(void)
{
	int i;
	struct bt_msg *bt_msg;
	struct ipmi_msg *ipmi_msg;
	uint8_t resp_len, netfn, seq, cmd;
	uint8_t cc = IPMI_CC_NO_ERROR;

	/* Wait for BMC to signal response */
	lock(&bt.msgq_lock);
	if (!(bt_inb(BT_CTRL) & BT_CTRL_B2H_ATN)) {
		unlock(&bt.msgq_lock);
		return true;
	}

	/* Indicate BMC that we are busy */
	bt_set_h_busy(true);

	/* Clear B2H_ATN and read pointer */
	bt_outb(BT_CTRL_B2H_ATN, BT_CTRL);
	bt_outb(BT_CTRL_CLR_RD_PTR, BT_CTRL);

	/* Read the response */
	/* Byte 1 - Length (includes header size) */
	resp_len = bt_inb(BT_HOST2BMC) - BT_MIN_RESP_LEN;

	/* Byte 2 - NetFn/LUN */
	netfn = bt_inb(BT_HOST2BMC);

	/* Byte 3 - Seq */
	seq = bt_inb(BT_HOST2BMC);

	/* Byte 4 - Cmd */
	cmd = bt_inb(BT_HOST2BMC);

	/* Byte 5 - Completion Code */
	cc = bt_inb(BT_HOST2BMC);

	/* Find the corresponding messasge */
	list_for_each(&bt.msgq, bt_msg, link) {
		if (bt_msg->seq == seq) {
			break;
		}

	}
	if (!bt_msg || (bt_msg->seq != seq)) {
		/* A response to a message we no longer care about. */
		prlog(PR_INFO, "BT: Nobody cared about a response to an BT/IPMI message\n");
		bt_flush_msg();
		bt_set_state(BT_STATE_B_BUSY);
		unlock(&bt.msgq_lock);
		return false;
	}

	ipmi_msg = &bt_msg->ipmi_msg;

	/*
	 * Make sure we have enough room to store the resposne. As all values
	 * are unsigned we will also trigger this error if
	 * bt_inb(BT_HOST2BMC) < BT_MIN_RESP_LEN (which should never occur).
	 */
	if (resp_len > ipmi_msg->resp_size) {
		prerror("BT: Invalid resp_len %d for ipmi_msg->cmd = 0x%02x\n", resp_len, ipmi_msg->cmd);
		resp_len = ipmi_msg->resp_size;
		cc = IPMI_ERR_MSG_TRUNCATED;
	}
	ipmi_msg->resp_size = resp_len;

	/* Byte 6:N - Data */
	for (i = 0; i < resp_len; i++)
		ipmi_msg->data[i] = bt_inb(BT_HOST2BMC);
	bt_set_h_busy(false);

	if (cc != IPMI_CC_NO_ERROR)
		prerror("BT: Host error 0x%02x receiving BT/IPMI response for msg 0x%02x\n", cc, seq);

	/* Make sure the other side is idle before we move to the idle state */
	bt_set_state(BT_STATE_B_BUSY);
	list_del(&bt_msg->link);
	bt.queue_len--;
	unlock(&bt.msgq_lock);

	/*
	 * Call the IPMI layer to finish processing the message.
	 */
#if BT_QUEUE_DEBUG
	prlog(PR_DEBUG, "cmd 0x%02x done\n", seq);
#endif

	ipmi_cmd_done(cmd, netfn, cc, ipmi_msg);

	/* Immediately send the next message */
	return false;
}

static void bt_expire_old_msg(void)
{
	unsigned long tb;
	struct bt_msg *bt_msg, *next;

	lock(&bt.msgq_lock);
	tb = mftb();
	list_for_each_safe(&bt.msgq, bt_msg, next, link) {
		if ((bt_msg->tb + BT_MSG_TIMEOUT) < tb) {
			prerror("BT: Expiring old messsage number 0x%02x\n", bt_msg->seq);
			bt_msg_del(bt_msg);
		}
	}
	unlock(&bt.msgq_lock);
}

static void bt_poll(void *data __unused)
{
	bool ret = true;

	do {

#if BT_QUEUE_DEBUG
		struct bt_msg *msg;
		static bool printed = false;
		lock(&bt.msgq_lock);
		if (!list_empty(&bt.msgq)) {
			printed = false;
			prlog(PR_DEBUG, "-------- BT Msg Queue --------\n");
			list_for_each(&bt.msgq, msg, link) {
				prlog(PR_DEBUG, "Seq: 0x%02x Cmd: 0x%02x\n", msg->seq, msg->ipmi_msg.cmd);
			}
			prlog(PR_DEBUG, "-----------------------------\n");
		} else if (!printed) {
			printed = true;
			prlog(PR_DEBUG, "----- BT Msg Queue Empty -----\n");
		}
		unlock(&bt.msgq_lock);
#endif

		ret = true;
		if (try_lock(&bt.bt_lock)) {
			bt_expire_old_msg();

			switch(bt.state) {
			case BT_STATE_IDLE:
				ret = bt_try_send_msg();
				break;

			case BT_STATE_RESP_WAIT:
				ret = bt_get_resp();
				break;

			case BT_STATE_B_BUSY:
				if (bt_idle()) {
					bt_set_state(BT_STATE_IDLE);
					ret = false;
				}
				break;
			}
			unlock(&bt.bt_lock);
		}
	}
	while(!ret);
}

static int bt_add_ipmi_msg(struct ipmi_msg *ipmi_msg)
{
	struct bt_msg *bt_msg = container_of(ipmi_msg, struct bt_msg, ipmi_msg);

	lock(&bt.msgq_lock);
	bt_msg->tb = mftb();
	bt_msg->seq = ipmi_seq++;
	list_add_tail(&bt.msgq, &bt_msg->link);
	bt.queue_len++;
	if (bt.queue_len > BT_MAX_QUEUE_LEN) {
		/* Maximum ueue lenght exceeded - remove the oldest message
		   from the queue. */
		prerror("BT: Maximum queue length exceeded\n");
		bt_msg = list_tail(&bt.msgq, struct bt_msg, link);
		assert(bt_msg);
		bt_msg_del(bt_msg);
	}
	unlock(&bt.msgq_lock);

	bt_poll(NULL);

	return 0;
}

void bt_irq(void)
{
	uint8_t ireg = bt_inb(BT_INTMASK);

	if (ireg & BT_INTMASK_B2H_IRQ) {
		bt_outb(BT_INTMASK_B2H_IRQ | BT_INTMASK_B2H_IRQEN, BT_INTMASK);
		bt_poll(NULL);
	}
}

/*
 * Allocate an ipmi message and bt container and return the ipmi
 * message struct. Allocates enough space for the request and response
 * data.
 */
static struct ipmi_msg *bt_alloc_ipmi_msg(size_t request_size, size_t response_size)
{
	struct bt_msg *bt_msg;

	bt_msg = zalloc(sizeof(struct bt_msg) + MAX(request_size, response_size));
	if (!bt_msg)
		return NULL;

	bt_msg->ipmi_msg.req_size = request_size;
	bt_msg->ipmi_msg.resp_size = response_size;
	bt_msg->ipmi_msg.data = (uint8_t *) (bt_msg + 1);

	return &bt_msg->ipmi_msg;
}

/*
 * Free a previously allocated ipmi message.
 */
static void bt_free_ipmi_msg(struct ipmi_msg *ipmi_msg)
{
	struct bt_msg *bt_msg = container_of(ipmi_msg, struct bt_msg, ipmi_msg);

	free(bt_msg);
}

/*
 * Remove a message from the queue. The memory allocated for the ipmi message
 * will need to be freed by the caller with bt_free_ipmi_msg() as it will no
 * longer be in the queue of messages.
 */
static int bt_del_ipmi_msg(struct ipmi_msg *ipmi_msg)
{
	struct bt_msg *bt_msg = container_of(ipmi_msg, struct bt_msg, ipmi_msg);

	lock(&bt.msgq_lock);
	list_del(&bt_msg->link);
	bt.queue_len--;
	unlock(&bt.msgq_lock);
	return 0;
}

struct ipmi_backend bt_backend = {
	.alloc_msg = bt_alloc_ipmi_msg,
	.free_msg = bt_free_ipmi_msg,
	.queue_msg = bt_add_ipmi_msg,
	.dequeue_msg = bt_del_ipmi_msg,
};

void bt_init(void)
{
	struct dt_node *n;
	const struct dt_property *prop;

	/* We support only one */
	n = dt_find_compatible_node(dt_root, NULL, "ipmi-bt");
	if (!n)
		return;

	/* Get IO base */
	prop = dt_find_property(n, "reg");
	if (!prop) {
		prerror("BT: Can't find reg property\n");
		return;
	}
	if (dt_property_get_cell(prop, 0) != OPAL_LPC_IO) {
		prerror("BT: Only supports IO addresses\n");
		return;
	}
	bt.base_addr = dt_property_get_cell(prop, 1);
	printf("BT: Interface intialized, IO 0x%04x\n", bt.base_addr);

	bt_init_interface();
	init_lock(&bt.msgq_lock);
	init_lock(&bt.bt_lock);

	/*
	 * The iBT interface comes up in the busy state until the daemon has
	 * initialised it.
	 */
	bt_set_state(BT_STATE_B_BUSY);
	list_head_init(&bt.msgq);
	bt.queue_len = 0;

	opal_add_poller(bt_poll, NULL);

	ipmi_register_backend(&bt_backend);
}
