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
#include <lock.h>
#include <timebase.h>
#include <time.h>
#include <fsp-elog.h>

//#define DBG(fmt...)	printf("RTC: " fmt)
#define DBG(fmt...)	do { } while(0)

/*
 * Note on how those operate:
 *
 * Because the RTC calls can be pretty slow, these functions will shoot
 * an asynchronous request to the FSP (if none is already pending)
 *
 * The requests will return OPAL_BUSY_EVENT as long as the event has
 * not been completed.
 *
 * WARNING: An attempt at doing an RTC write while one is already pending
 * will simply ignore the new arguments and continue returning
 * OPAL_BUSY_EVENT. This is to be compatible with existing Linux code.
 *
 * Completion of the request will result in an event OPAL_EVENT_RTC
 * being signaled, which will remain raised until a corresponding call
 * to opal_rtc_read() or opal_rtc_write() finally returns OPAL_SUCCESS,
 * at which point the operation is complete and the event cleared.
 *
 * If we end up taking longer than rtc_read_timeout_ms millieconds waiting
 * for the response from a read request, we simply return a cached value (plus
 * an offset calculated from the timebase. When the read request finally
 * returns, we update our cache value accordingly.
 *
 * There is two separate set of state for reads and writes. If both are
 * attempted at the same time, the event bit will remain set as long as either
 * of the two has a pending event to signal.
 */

enum {
	RTC_TOD_VALID,
	RTC_TOD_INVALID,
	RTC_TOD_PERMANENT_ERROR,
} rtc_tod_state = RTC_TOD_INVALID;

static struct lock rtc_lock;
static struct fsp_msg *rtc_read_msg;
static struct fsp_msg *rtc_write_msg;
/* TODO We'd probably want to export and use this variable declared in fsp.c,
 * instead of each component individually maintaining the state.. may be for
 * later optimization
 */
static bool fsp_in_reset = false;

/* last synchonisation point */
static struct {
	struct tm	tm;
	unsigned long	tb;
	bool		dirty;
} rtc_tod_cache;

/* Timebase value when we last initiated a RTC read request */
static unsigned long read_req_tb;

/* If a RTC read takes longer than this, we return a value generated
 * from the cache + timebase */
static const int rtc_read_timeout_ms = 1500;

DEFINE_LOG_ENTRY(OPAL_RC_RTC_TOD, OPAL_PLATFORM_ERR_EVT, OPAL_RTC,
			OPAL_PLATFORM_FIRMWARE, OPAL_INFO,
			OPAL_NA, NULL);

DEFINE_LOG_ENTRY(OPAL_RC_RTC_READ, OPAL_PLATFORM_ERR_EVT, OPAL_RTC,
			OPAL_PLATFORM_FIRMWARE, OPAL_INFO,
			OPAL_NA, NULL);

static int days_in_month(int month, int year)
{
	static int month_days[] = {
		31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
	};

	assert(1 <= month && month <= 12);

	/* we may need to update this in the year 4000, pending a
	 * decision on whether or not it's a leap year */
	if (month == 2) {
		bool is_leap = !(year % 400) || ((year % 100) && !(year % 4));
		return is_leap ? 29 : 28;
	}

	return month_days[month - 1];
}

static void tm_add(struct tm *in, struct tm *out, unsigned long secs)
{
	unsigned long year, month, mday, hour, minute, second, d;
	static const unsigned long sec_in_400_years =
		((3903ul * 365) + (97 * 366)) * 24 * 60 * 60;

	assert(in);
	assert(out);

	second = in->tm_sec;
	minute = in->tm_min;
	hour = in->tm_hour;
	mday = in->tm_mday;
	month = in->tm_mon;
	year = in->tm_year;

	second += secs;

	/* There are the same number of seconds in any 400-year block; this
	 * limits the iterations in the loop below */
	year += 400 * (second / sec_in_400_years);
	second = second % sec_in_400_years;

	if (second >= 60) {
		minute += second / 60;
		second = second % 60;
	}

	if (minute >= 60) {
		hour += minute / 60;
		minute = minute % 60;
	}

	if (hour >= 24) {
		mday += hour / 24;
		hour = hour % 24;
	}

	for (d = days_in_month(month, year); mday >= d;
			d = days_in_month(month, year)) {
		month++;
		if (month > 12) {
			month = 1;
			year++;
		}
		mday -= d;
	}

	out->tm_year = year;
	out->tm_mon = month;
	out->tm_mday = mday;
	out->tm_hour = hour;
	out->tm_min = minute;
	out->tm_sec = second;
}

/* MSB is byte 3, LSB is byte 0 */
static unsigned int bcd_byte(uint32_t bcd, int byteno)
{
	bcd >>= byteno * 8;
	return (bcd >> 4 & 0xf) * 10 + (bcd & 0xf);
}

static uint32_t int_to_bcd2(unsigned int x)
{
	return (((x / 10) << 4) & 0xf0) | (x % 10);
}

static uint32_t int_to_bcd4(unsigned int x)
{
	return int_to_bcd2(x / 100) << 8 | int_to_bcd2(x % 100);
}

static void rtc_to_tm(struct fsp_msg *msg, struct tm *tm)
{
	uint32_t x;

	/* The FSP returns in BCD:
	 *
	 *  |      year       | month |   mday   |
	 *  +------------------------------------+
	 *  |  hour  | minute | secs  | reserved |
	 *  +------------------------------------+
	 *  |             microseconds           |
	 */
	x = msg->data.words[0];
	tm->tm_year = bcd_byte(x, 3) * 100 + bcd_byte(x, 2);
	tm->tm_mon = bcd_byte(x, 1);
	tm->tm_mday = bcd_byte(x, 0);

	x = msg->data.words[1];
	tm->tm_hour = bcd_byte(x, 3);
	tm->tm_min = bcd_byte(x, 2);
	tm->tm_sec = bcd_byte(x, 1);
}

static void tm_to_datetime(struct tm *tm, uint32_t *y_m_d, uint64_t *h_m_s_m)
{
	uint64_t h_m_s;
	/*
	 * The OPAL API is defined as returned a u64 of a similar
	 * format to the FSP message; the 32-bit date field is
	 * in the format:
	 *
	 * |  year | year | month  | day |
	 *
	 */
	*y_m_d = int_to_bcd4(tm->tm_year) << 16 |
		 int_to_bcd2(tm->tm_mon) << 8 |
		 int_to_bcd2(tm->tm_mday);

	/*
	 * ... and the 64-bit time field is in the format
	 *
	 *  |  hour  | minutes | secs  | millisec |
	 *  | -------------------------------------
	 *  |        millisec          | reserved |
	 *
	 * We simply ignore the microseconds/milliseconds for now
	 * as I don't quite understand why the OPAL API defines that
	 * it needs 6 digits for the milliseconds :-) I suspect the
	 * doc got that wrong and it's supposed to be micro but
	 * let's ignore it.
	 *
	 * Note that Linux doesn't use nor set the ms field anyway.
	 */
	h_m_s = int_to_bcd2(tm->tm_hour) << 24 |
	        int_to_bcd2(tm->tm_min) << 16 |
	        int_to_bcd2(tm->tm_sec) << 8;

	*h_m_s_m = h_m_s << 32;
}

static void fsp_rtc_process_read(struct fsp_msg *read_resp)
{
	int val = (read_resp->word1 >> 8) & 0xff;

	switch (val) {
	case 0xa9:
		log_simple_error(&e_info(OPAL_RC_RTC_TOD),
				"RTC TOD in invalid state\n");
		rtc_tod_state = RTC_TOD_INVALID;
		break;

	case 0xaf:
		log_simple_error(&e_info(OPAL_RC_RTC_TOD),
			"RTC TOD in permanent error state\n");
		rtc_tod_state = RTC_TOD_PERMANENT_ERROR;
		break;

	case 0:
		/* Save the read RTC value in our cache */
		rtc_to_tm(read_resp, &rtc_tod_cache.tm);
		rtc_tod_cache.tb = mftb();
		rtc_tod_state = RTC_TOD_VALID;
		break;

	default:
		log_simple_error(&e_info(OPAL_RC_RTC_TOD),
				"RTC TOD read failed: %d\n", val);
		rtc_tod_state = RTC_TOD_INVALID;
	}
}

static void opal_rtc_eval_events(void)
{
	bool pending = false;

	if (rtc_read_msg && !fsp_msg_busy(rtc_read_msg))
		pending = true;
	if (rtc_write_msg && !fsp_msg_busy(rtc_write_msg))
		pending = true;
	opal_update_pending_evt(OPAL_EVENT_RTC, pending ? OPAL_EVENT_RTC : 0);
}

static void fsp_rtc_req_complete(struct fsp_msg *msg)
{
	lock(&rtc_lock);
	DBG("RTC completion %p\n", msg);
	if (msg == rtc_read_msg)
		fsp_rtc_process_read(msg->resp);
	opal_rtc_eval_events();
	unlock(&rtc_lock);
}

static int64_t fsp_rtc_send_read_request(void)
{
	struct fsp_msg *msg;
	int rc;

	msg = fsp_mkmsg(FSP_CMD_READ_TOD, 0);
	if (!msg) {
		log_simple_error(&e_info(OPAL_RC_RTC_READ),
			"RTC: failed to allocate read message\n");
		return OPAL_INTERNAL_ERROR;
	}

	rc = fsp_queue_msg(msg, fsp_rtc_req_complete);
	if (rc) {
		fsp_freemsg(msg);
		log_simple_error(&e_info(OPAL_RC_RTC_READ),
			"RTC: failed to queue read message: %d\n", rc);
		return OPAL_INTERNAL_ERROR;
	}

	read_req_tb = mftb();
	rtc_read_msg = msg;

	return OPAL_BUSY_EVENT;
}

static void encode_cached_tod(uint32_t *year_month_day,
		uint64_t *hour_minute_second_millisecond)
{
	unsigned long cache_age_sec;
	struct tm tm;

	cache_age_sec = tb_to_msecs(mftb() - rtc_tod_cache.tb) / 1000;

	tm_add(&rtc_tod_cache.tm, &tm, cache_age_sec);

	/* Format to OPAL API values */
	tm_to_datetime(&tm, year_month_day, hour_minute_second_millisecond);
}

int fsp_rtc_get_cached_tod(uint32_t *year_month_day,
		uint64_t *hour_minute_second_millisecond)
{

	if (rtc_tod_state != RTC_TOD_VALID)
		return -1;

	encode_cached_tod(year_month_day,
			hour_minute_second_millisecond);
	return 0;
}

static int64_t fsp_opal_rtc_read(uint32_t *year_month_day,
				 uint64_t *hour_minute_second_millisecond)
{
	struct fsp_msg *msg;
	int64_t rc;

	if (!year_month_day || !hour_minute_second_millisecond)
		return OPAL_PARAMETER;

	lock(&rtc_lock);
	/* During R/R of FSP, read cached TOD */
	if (fsp_in_reset) {
		fsp_rtc_get_cached_tod(year_month_day,
				hour_minute_second_millisecond);
		rc = OPAL_SUCCESS;
		goto out;
	}

	msg = rtc_read_msg;

	if (rtc_tod_state == RTC_TOD_PERMANENT_ERROR) {
		if (msg && !fsp_msg_busy(msg))
			fsp_freemsg(msg);
		rc = OPAL_HARDWARE;
		goto out;
	}

	/* If we don't have a read pending already, fire off a request and
	 * return */
	if (!msg) {
		DBG("Sending new RTC read request\n");
		rc = fsp_rtc_send_read_request();

	/* If our pending read is done, clear events and return the time
	 * from the cache */
	} else if (!fsp_msg_busy(msg)) {
		DBG("RTC read complete, state %d\n", rtc_tod_state);

		rtc_read_msg = NULL;
		opal_rtc_eval_events();
		fsp_freemsg(msg);

		if (rtc_tod_state == RTC_TOD_VALID) {
			encode_cached_tod(year_month_day,
					hour_minute_second_millisecond);
			rc = OPAL_SUCCESS;
		} else
			rc = OPAL_INTERNAL_ERROR;

	/* Timeout: return our cached value (updated from tb), but leave the
	 * read request pending so it will update the cache later */
	} else if (mftb() > read_req_tb + msecs_to_tb(rtc_read_timeout_ms)) {
		DBG("RTC read timed out\n");

		encode_cached_tod(year_month_day,
				hour_minute_second_millisecond);
		rc = OPAL_SUCCESS;

	/* Otherwise, we're still waiting on the read to complete */
	} else {
		rc = OPAL_BUSY_EVENT;
	}
out:
	unlock(&rtc_lock);
	return rc;
}

static int64_t fsp_opal_rtc_write(uint32_t year_month_day,
				  uint64_t hour_minute_second_millisecond)
{
	struct fsp_msg *msg;
	uint32_t w0, w1, w2;
	int64_t rc;

	lock(&rtc_lock);
	if (rtc_tod_state == RTC_TOD_PERMANENT_ERROR) {
		rc = OPAL_HARDWARE;
		msg = NULL;
		goto bail;
	}

	/* Do we have a request already ? */
	msg = rtc_write_msg;
	if (msg) {
		/* If it's still in progress, return */
		if (fsp_msg_busy(msg)) {
			/* Don't free the message */
			msg = NULL;
			rc = OPAL_BUSY_EVENT;
			goto bail;
		}

		DBG("Completed write request @%p, state=%d\n", msg, msg->state);
		/* It's complete, clear events */
		rtc_write_msg = NULL;
		opal_rtc_eval_events();

		/* Check error state */
		if (msg->state != fsp_msg_done) {
			DBG(" -> request not in done state -> error !\n");
			rc = OPAL_INTERNAL_ERROR;
			goto bail;
		}
		rc = OPAL_SUCCESS;
		goto bail;
	}

	DBG("Sending new write request...\n");

	/* Create a request and send it. Just like for read, we ignore
	 * the "millisecond" field which is probably supposed to be
	 * microseconds and which Linux ignores as well anyway
	 */
	w0 = year_month_day;
	w1 = (hour_minute_second_millisecond >> 32) & 0xffffff00;
	w2 = 0;
	
	rtc_write_msg = fsp_mkmsg(FSP_CMD_WRITE_TOD, 3, w0, w1, w2);
	if (!rtc_write_msg) {
		DBG(" -> allocation failed !\n");
		rc = OPAL_INTERNAL_ERROR;
		goto bail;
	}
	DBG(" -> req at %p\n", rtc_write_msg);

	if (fsp_in_reset) {
		rtc_to_tm(rtc_write_msg,  &rtc_tod_cache.tm);
		rtc_tod_cache.tb = mftb();
		rtc_tod_cache.dirty = true;
		fsp_freemsg(rtc_write_msg);
		rtc_write_msg = NULL;
		rc = OPAL_SUCCESS;
		goto bail;
	} else if (fsp_queue_msg(rtc_write_msg, fsp_rtc_req_complete)) {
		DBG(" -> queueing failed !\n");
		rc = OPAL_INTERNAL_ERROR;
		fsp_freemsg(rtc_write_msg);
		rtc_write_msg = NULL;
		goto bail;
	}
	rc = OPAL_BUSY_EVENT;
 bail:
	unlock(&rtc_lock);
	if (msg)
		fsp_freemsg(msg);
	return rc;
}

static void rtc_flush_cached_tod(void)
{
	struct fsp_msg *msg;
	uint64_t h_m_s_m;
	uint32_t y_m_d;

	if (fsp_rtc_get_cached_tod(&y_m_d, &h_m_s_m))
		return;
	msg = fsp_mkmsg(FSP_CMD_WRITE_TOD, 3, y_m_d,
			(h_m_s_m >> 32) & 0xffffff00, 0);
	if (msg)
		fsp_queue_msg(msg, fsp_freemsg);
}

static bool fsp_rtc_msg_rr(u32 cmd_sub_mod, struct fsp_msg *msg)
{

	int rc = false;
	assert(msg == NULL);

	switch (cmd_sub_mod) {
	case FSP_RESET_START:
		lock(&rtc_lock);
		fsp_in_reset = true;
		unlock(&rtc_lock);
		rc = true;
		break;
	case FSP_RELOAD_COMPLETE:
		lock(&rtc_lock);
		fsp_in_reset = false;
		if (rtc_tod_cache.dirty) {
			rtc_flush_cached_tod();
			rtc_tod_cache.dirty = false;
		}
		unlock(&rtc_lock);
		rc = true;
		break;
	}

	return rc;
}

static struct fsp_client fsp_rtc_client_rr = {
	.message = fsp_rtc_msg_rr,
};

void fsp_rtc_init(void)
{
	struct fsp_msg msg, resp;
	int rc;

	if (!fsp_present()) {
		rtc_tod_state = RTC_TOD_PERMANENT_ERROR;
		return;
	}

	opal_register(OPAL_RTC_READ, fsp_opal_rtc_read, 2);
	opal_register(OPAL_RTC_WRITE, fsp_opal_rtc_write, 2);

	/* Register for the reset/reload event */
	fsp_register_client(&fsp_rtc_client_rr, FSP_MCLASS_RR_EVENT);

	msg.resp = &resp;
	fsp_fillmsg(&msg, FSP_CMD_READ_TOD, 0);

	DBG("Getting initial RTC TOD\n");

	lock(&rtc_lock);

	rc = fsp_sync_msg(&msg, false);

	if (rc >= 0)
		fsp_rtc_process_read(&resp);
	else
		rtc_tod_state = RTC_TOD_PERMANENT_ERROR;

	unlock(&rtc_lock);
}
