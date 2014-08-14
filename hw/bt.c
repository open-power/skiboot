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
	struct ipmi_msg *ipmi_msg;
	uint8_t seq;
	uint8_t lun;
};

struct bt {
	uint32_t base_addr;
	enum bt_states state;
	struct lock lock;
	struct list_head msgq;
	void (*ipmi_cmd_done)(struct ipmi_msg *);
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
	struct bt_msg *bt_msg = malloc(sizeof(struct bt_msg));

	if (!bt_msg)
		return -1;

	bt_msg->lun = 0;
	bt_msg->seq = ipmi_seq++;
	bt_msg->ipmi_msg = ipmi_msg;
	list_add_tail(&bt.msgq, &bt_msg->link);

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

	bt_msg = list_top(&bt.msgq, struct bt_msg, link);
	if (!bt_msg)
		return true;

	ipmi_msg = bt_msg->ipmi_msg;

	if (!bt_idle()) {
		prerror("BT: Interface in an unexpected state, attempting reset\n");
		bt_reset_interface();
		return false;
	}

	/* Send the message */
	bt_setmask(BT_CTRL_CLR_WR_PTR, BT_CTRL);

	/* Byte 1 - Length */
	bt_outb(ipmi_msg->req_data_len + BT_MIN_REQ_LEN, BT_HOST2BMC);

	/* Byte 2 - NetFn/LUN */
	bt_outb((ipmi_msg->netfn << 2) | (bt_msg->lun & 0x3), BT_HOST2BMC);

	/* Byte 3 - Seq */
	bt_outb(bt_msg->seq, BT_HOST2BMC);

	/* Byte 4 - Cmd */
	bt_outb(ipmi_msg->cmd, BT_HOST2BMC);

	/* Byte 5:N - Data */
	for (i = 0; i < ipmi_msg->req_data_len; i++)
		bt_outb(ipmi_msg->req_data[i], BT_HOST2BMC);

	bt_setmask(BT_CTRL_H2B_ATN, BT_CTRL);
	bt_set_state(BT_STATE_RESP_WAIT);
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
	uint8_t resp_len;
	uint8_t netfn;
	uint8_t cc = IPMI_CC_NO_ERROR;

	/* Wait for BMC to signal response */
	if (!(bt_inb(BT_CTRL) & BT_CTRL_B2H_ATN))
		return true;

	bt_msg = list_top(&bt.msgq, struct bt_msg, link);
	if (!bt_msg) {
		/* A response to a message we no longer care about. */
		prlog(PR_INFO, "BT: Nobody cared about a response to an BT/IPMI message\n");
		bt_flush_msg();
		bt_set_state(BT_STATE_B_BUSY);
		return false;
	}

	ipmi_msg = bt_msg->ipmi_msg;
	bt_setmask(BT_CTRL_H_BUSY, BT_CTRL);
	bt_clearmask(BT_CTRL_B2H_ATN, BT_CTRL);
	bt_setmask(BT_CTRL_CLR_RD_PTR, BT_CTRL);

	/* Read the response */
	/* Byte 1 - Length (includes header size) */
	resp_len = bt_inb(BT_HOST2BMC) - BT_MIN_RESP_LEN;

	/*
	 * Make sure we have enough room to store the resposne. As all values
	 * are unsigned we will also trigger this error if
	 * bt_inb(BT_HOST2BMC) < BT_MIN_RESP_LEN (which should never occur).
	 */
	if (resp_len > ipmi_msg->resp_data_len) {
		prerror("BT: Invalid resp_len %d for ipmi_msg->cmd = 0x%02x\n", resp_len, ipmi_msg->cmd);
		resp_len = ipmi_msg->resp_data_len;
		cc = IPMI_ERR_MSG_TRUNCATED;
	}
	ipmi_msg->resp_data_len = resp_len;

	/* Byte 2 - NetFn/LUN */
	netfn = bt_inb(BT_HOST2BMC);
	ipmi_msg->netfn = netfn >> 2;
	bt_msg->lun = netfn & 0x3;

	/* Byte 3 - Seq */
	bt_msg->seq = bt_inb(BT_HOST2BMC);

	/* Byte 4 - Cmd */
	ipmi_msg->cmd = bt_inb(BT_HOST2BMC);

	/* Byte 5 - Completion Code */
	ipmi_msg->cc = bt_inb(BT_HOST2BMC);

	/* Byte 6:N - Data */
	for (i = 0; i < resp_len; i++)
		ipmi_msg->resp_data[i] = bt_inb(BT_HOST2BMC);
	bt_clearmask(BT_CTRL_H_BUSY, BT_CTRL);

	if (cc != IPMI_CC_NO_ERROR) {
		prerror("BT: Host error 0x%02x receiving BT/IPMI response\n", cc);
		ipmi_msg->cc = cc;
	}

	/* Make sure the other side is idle before we move to the idle state */
	bt_set_state(BT_STATE_B_BUSY);
	list_del(&bt_msg->link);

	/*
	 * Call the IPMI layer to finish processing the message.
	 */
	if (bt.ipmi_cmd_done)
		bt.ipmi_cmd_done(ipmi_msg);

	/*
	 * The IPMI layer should have freed any data it allocated for the IPMI
	 * message in the completion function above.
	 */
	free(bt_msg);

	/* Immediately send the next message */
	return false;
}

static void bt_poll(void)
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
 * Crank the state machine to wait for a specific state. Returns true on
 * success and false if there is a timeout.
 */
static bool bt_wait_state(enum bt_states state)
{
	int timeout;
	struct timespec ts;

	ts.tv_sec = 0;
	ts.tv_nsec = 100000;
	for (timeout = POLL_TIMEOUT; timeout > 0; timeout--) {
		if (bt.state == state)
			return true;
		bt_poll();
		nanosleep(&ts, NULL);
	}

	return false;
}

/*
 * Add an ipmi message to the queue and wait for a response.
 */
int bt_add_ipmi_msg_wait(struct ipmi_msg *msg)
{
	int ret = 0;

	/*
	 * TODO: We may need finer grained locks if we start using an
	 * asynchronous operation model, but this should be fine for the moment.
	 */
	lock(&bt.lock);
	if (!bt_wait_state(BT_STATE_IDLE)) {
		ret = -1;
		goto out;
	}

	if (bt_add_ipmi_msg(msg)) {
		ret = -1;
		goto out;
	}

	/* Make sure we get out of the idle state */
	bt_poll();

	if (!bt_wait_state(BT_STATE_IDLE)) {
		ret = -1;
		goto out;
	}

out:
	unlock(&bt.lock);
	return ret;
}

void bt_del_ipmi_msg(struct ipmi_msg *ipmi_msg)
{
	struct bt_msg *bt_msg;
	struct bt_msg *next;

	lock(&bt.lock);
	list_for_each_safe(&bt.msgq, bt_msg, next, link) {
		if (bt_msg->ipmi_msg == ipmi_msg) {
			list_del(&bt_msg->link);
			break;
		}
	}
	unlock(&bt.lock);
}

void bt_init(void (*ipmi_cmd_done)(struct ipmi_msg *))
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
	bt.ipmi_cmd_done = ipmi_cmd_done;
	list_head_init(&bt.msgq);
}
