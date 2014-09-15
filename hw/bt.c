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
#include <time.h>
#include <ipmi.h>
#include <bt.h>

/* BT registers */
#define BT_CTRL			0
#define   BT_CTRL_B_BUSY	0x00000080
#define   BT_CTRL_H_BUSY	0x00000040
#define   BT_CTRL_OEM0		0x00000020
#define   BT_CTRL_SMS_ATN	0x00000010
#define   BT_CTRL_B2H_ATN	0x00000008
#define   BT_CTRL_H2B_ATN	0x00000004
#define   BT_CTRL_CLR_RD_PTR	0x00000002
#define   BT_CTRL_CLR_WR_PTR	0x00000001
#define BT_HOST2BMC		1
#define BT_INTMASK		2
#define   BT_INTMASK_BMC_HWRST	0x00000001

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
	uint8_t seq;
	uint8_t lun;
	struct ipmi_msg ipmi_msg;
};

struct bt {
	uint32_t base_addr;
	enum bt_states state;
	struct lock lock;
	struct list_head msgq;
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

static inline bool bt_idle(void)
{
	return !(bt_inb(BT_CTRL) & (BT_CTRL_B_BUSY | BT_CTRL_H2B_ATN));
}

static void bt_setmask(uint8_t mask, uint32_t reg)
{
	uint8_t tmp;
	tmp = bt_inb(reg);
	bt_outb(tmp | mask, reg);
}

static void bt_clearmask(uint8_t mask, uint32_t reg)
{
	uint8_t tmp;
	tmp = bt_inb(reg);
	bt_outb(tmp & ~mask, reg);
}

static inline void bt_set_state(enum bt_states next_state)
{
	bt.state = next_state;
}

static int bt_add_ipmi_msg(struct ipmi_msg *ipmi_msg)
{
	struct bt_msg *bt_msg = container_of(ipmi_msg, struct bt_msg, ipmi_msg);

	bt_msg->lun = 0;
	lock(&bt.lock);
	bt_msg->seq = ipmi_seq++;
	list_add_tail(&bt.msgq, &bt_msg->link);
	unlock(&bt.lock);

	return 0;
}

static void bt_reset_interface(void)
{
	bt_setmask(BT_INTMASK_BMC_HWRST, BT_INTMASK);
	bt_set_state(BT_STATE_B_BUSY);
}

static bool bt_try_send_msg(void)
{
	int i;
	struct bt_msg *bt_msg;
	struct ipmi_msg *ipmi_msg;

	lock(&bt.lock);
	bt_msg = list_top(&bt.msgq, struct bt_msg, link);
	if (!bt_msg) {
		unlock(&bt.lock);
		return true;
	}

	ipmi_msg = &bt_msg->ipmi_msg;

	if (!bt_idle()) {
		prerror("BT: Interface in an unexpected state, attempting reset\n");
		bt_reset_interface();
		unlock(&bt.lock);
		return false;
	}

	/* Send the message */
	bt_setmask(BT_CTRL_CLR_WR_PTR, BT_CTRL);

	/* Byte 1 - Length */
	bt_outb(ipmi_msg->req_size + BT_MIN_REQ_LEN, BT_HOST2BMC);

	/* Byte 2 - NetFn/LUN */
	bt_outb((ipmi_msg->netfn << 2) | (bt_msg->lun & 0x3), BT_HOST2BMC);

	/* Byte 3 - Seq */
	bt_outb(bt_msg->seq, BT_HOST2BMC);

	/* Byte 4 - Cmd */
	bt_outb(ipmi_msg->cmd, BT_HOST2BMC);

	/* Byte 5:N - Data */
	for (i = 0; i < ipmi_msg->req_size; i++)
		bt_outb(ipmi_msg->data[i], BT_HOST2BMC);

	bt_setmask(BT_CTRL_H2B_ATN, BT_CTRL);
	bt_set_state(BT_STATE_RESP_WAIT);
	unlock(&bt.lock);

	return true;
}

static void bt_flush_msg(void)
{
	bt_setmask(BT_CTRL_H_BUSY, BT_CTRL);
	bt_clearmask(BT_CTRL_B2H_ATN, BT_CTRL);
	bt_setmask(BT_CTRL_CLR_RD_PTR, BT_CTRL);
	bt_clearmask(BT_CTRL_H_BUSY, BT_CTRL);
}

static bool bt_get_resp(void)
{
	int i;
	struct bt_msg *bt_msg;
	struct ipmi_msg *ipmi_msg;
	uint8_t resp_len, netfn, seq, cmd;
	uint8_t cc = IPMI_CC_NO_ERROR;

	/* Wait for BMC to signal response */
	lock(&bt.lock);
	if (!(bt_inb(BT_CTRL) & BT_CTRL_B2H_ATN)) {
		unlock(&bt.lock);
		return true;
	}

	bt_setmask(BT_CTRL_H_BUSY, BT_CTRL);
	bt_clearmask(BT_CTRL_B2H_ATN, BT_CTRL);
	bt_setmask(BT_CTRL_CLR_RD_PTR, BT_CTRL);

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
		unlock(&bt.lock);
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

	bt_msg->lun = netfn & 0x3;
	netfn = netfn >> 2;

	/* Byte 6:N - Data */
	for (i = 0; i < resp_len; i++)
		ipmi_msg->data[i] = bt_inb(BT_HOST2BMC);
	bt_clearmask(BT_CTRL_H_BUSY, BT_CTRL);

	if (cc != IPMI_CC_NO_ERROR)
		prerror("BT: Host error 0x%02x receiving BT/IPMI response\n", cc);

	/* Make sure the other side is idle before we move to the idle state */
	bt_set_state(BT_STATE_B_BUSY);
	list_del(&bt_msg->link);
	unlock(&bt.lock);

	/*
	 * Call the IPMI layer to finish processing the message.
	 */
	ipmi_cmd_done(cmd, netfn, cc, ipmi_msg);

	/* Immediately send the next message */
	return false;
}

static void bt_poll(void *data __unused)
{
	bool ret = true;

	do {
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
	}
	while(!ret);
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

	lock(&bt.lock);
	list_del(&bt_msg->link);
	unlock(&bt.lock);
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
	bt_reset_interface();
	init_lock(&bt.lock);

	/*
	 * The iBT interface comes up in the busy state until the daemon has
	 * initialised it.
	 */
	bt_set_state(BT_STATE_B_BUSY);
	list_head_init(&bt.msgq);

	opal_add_poller(bt_poll, NULL);

	ipmi_register_backend(&bt_backend);
}
