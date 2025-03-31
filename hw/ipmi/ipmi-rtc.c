// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Talk to a Real Time Clock (RTC) over IPMI
 *
 * Copyright 2013-2015 IBM Corp.
 */

#include <stdlib.h>
#include <string.h>
#include <ipmi.h>
#include <lock.h>
#include <time.h>
#include <time-utils.h>
#include <device.h>
#include <opal.h>
#include <rtc.h>

static struct lock time_lock = LOCK_UNLOCKED;
static enum {
	idle,
	waiting,
	read_updated,
	write_success,
	read_error,
	write_error,
	write_wrong_state,
} time_status;

static void get_sel_time_error(struct ipmi_msg *msg)
{
	lock(&time_lock);
	time_status = read_error;
	unlock(&time_lock);
	ipmi_free_msg(msg);
}

static void get_sel_time_complete(struct ipmi_msg *msg)
{
	struct tm tm;
	le32 result;
	time_t time;

	memcpy(&result, msg->data, 4);
	time = le32_to_cpu(result);
	gmtime_r(&time, &tm);
	lock(&time_lock);
	rtc_cache_update(&tm);
	time_status = read_updated;
	unlock(&time_lock);
	ipmi_free_msg(msg);
}

static void set_sel_time_error(struct ipmi_msg *msg)
{
	lock(&time_lock);
	if (msg->cc == IPMI_NOT_IN_MY_STATE_ERR) {
		/* BMC in NTP mode does not allow this */
		time_status = write_wrong_state;
	} else {
		time_status = write_error;
	}
	unlock(&time_lock);
	ipmi_free_msg(msg);
}

static void set_sel_time_complete(struct ipmi_msg *msg)
{
	lock(&time_lock);
	time_status = write_success;
	unlock(&time_lock);
	ipmi_free_msg(msg);
}

static int64_t ipmi_get_sel_time(void)
{
	struct ipmi_msg *msg;

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, IPMI_GET_SEL_TIME,
			 get_sel_time_complete, NULL, NULL, 0, 4);
	if (!msg)
		return OPAL_HARDWARE;

	msg->error = get_sel_time_error;

	return ipmi_queue_msg(msg);
}

static int64_t ipmi_set_sel_time(uint32_t _tv)
{
	struct ipmi_msg *msg;
	const le32 tv = cpu_to_le32(_tv);

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, IPMI_SET_SEL_TIME,
			 set_sel_time_complete, NULL, (void *)&tv, sizeof(tv), 0);
	if (!msg)
		return OPAL_HARDWARE;

	msg->error = set_sel_time_error;

	return ipmi_queue_msg(msg);
}

static int64_t ipmi_opal_rtc_read(__be32 *__ymd, __be64 *__hmsm)
{
	uint32_t ymd;
	uint64_t hmsm;

	if (!__ymd || !__hmsm)
		return OPAL_PARAMETER;

	lock(&time_lock);
	switch (time_status) {
	case idle:
		time_status = waiting;
		unlock(&time_lock);
		return ipmi_get_sel_time();
	case read_updated:
		rtc_cache_get_datetime(&ymd, &hmsm);
		*__ymd = cpu_to_be32(ymd);
		*__hmsm = cpu_to_be64(hmsm);
		time_status = idle;
		unlock(&time_lock);
		return OPAL_SUCCESS;
	case waiting:
		unlock(&time_lock);
		return OPAL_BUSY_EVENT;
	case read_error:
		time_status = idle;
		unlock(&time_lock);
		return OPAL_HARDWARE;
	default:
		/* Clear out stale write status */
		time_status = idle;
		unlock(&time_lock);
		return OPAL_BUSY;
	}

	return OPAL_INTERNAL_ERROR;
}

static int64_t ipmi_opal_rtc_write(uint32_t year_month_day,
				  uint64_t hour_minute_second_millisecond)
{
	time_t t;
	struct tm tm;

	lock(&time_lock);
	switch (time_status) {
	case idle:
		time_status = waiting;
		unlock(&time_lock);
		datetime_to_tm(year_month_day, hour_minute_second_millisecond, &tm);
		t = mktime(&tm);
		return ipmi_set_sel_time(t);
	case write_success:
		time_status = idle;
		unlock(&time_lock);
		return OPAL_SUCCESS;
	case waiting:
		unlock(&time_lock);
		return OPAL_BUSY_EVENT;
	case write_error:
		time_status = idle;
		unlock(&time_lock);
		return OPAL_HARDWARE;
	case write_wrong_state:
		time_status = idle;
		unlock(&time_lock);
		return OPAL_WRONG_STATE;
	default:
		/* Clear out stale read status */
		time_status = idle;
		unlock(&time_lock);
		return OPAL_BUSY;
	}

	return OPAL_INTERNAL_ERROR;
}

void ipmi_rtc_init(void)
{
	struct dt_node *np = dt_new(opal_node, "rtc");
	dt_add_property_strings(np, "compatible", "ibm,opal-rtc");

	opal_register(OPAL_RTC_READ, ipmi_opal_rtc_read, 2);
	opal_register(OPAL_RTC_WRITE, ipmi_opal_rtc_write, 2);

	/* Initialise the rtc cache */
	ipmi_get_sel_time();
}
