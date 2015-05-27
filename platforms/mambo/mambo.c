/* Copyright 2015 IBM Corp.
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
#include <device.h>
#include <console.h>
#include <chip.h>
#include <opal-api.h>
#include <opal-internal.h>
#include <time-utils.h>
#include <time.h>

extern int64_t mambo_get_time(void);

static bool mambo_probe(void)
{
	if (!dt_find_by_path(dt_root, "/mambo"))
		return false;

	return true;
}

static int64_t mambo_rtc_read(uint32_t *ymd, uint64_t *hmsm)
{
	int64_t mambo_time;
	struct tm t;
	time_t mt;

	if (!ymd || !hmsm)
		return OPAL_PARAMETER;

	mambo_time = mambo_get_time();
	mt = mambo_time >> 32;
	gmtime_r(&mt, &t);
	tm_to_datetime(&t, ymd, hmsm);

	return OPAL_SUCCESS;
}

static void mambo_rtc_init(void)
{
	struct dt_node *np = dt_new(opal_node, "rtc");
	dt_add_property_strings(np, "compatible", "ibm,opal-rtc");

	opal_register(OPAL_RTC_READ, mambo_rtc_read, 2);
}

static void mambo_platform_init(void)
{
	force_dummy_console();
	mambo_rtc_init();
}

static int64_t mambo_cec_power_down(uint64_t request __unused)
{
	if (chip_quirk(QUIRK_MAMBO_CALLOUTS))
		mambo_sim_exit();

	return OPAL_UNSUPPORTED;
}

static int mambo_nvram_info(uint32_t *total_size)
{
	*total_size = 0x100000;
	return OPAL_SUCCESS;
}

static int mambo_nvram_start_read(void *dst, uint32_t src, uint32_t len)
{
	memset(dst+src, 0, len);

	nvram_read_complete(true);

	return OPAL_SUCCESS;
}

DECLARE_PLATFORM(mambo) = {
	.name			= "Mambo",
	.probe			= mambo_probe,
	.init		= mambo_platform_init,
	.cec_power_down = mambo_cec_power_down,
	.nvram_info		= mambo_nvram_info,
	.nvram_start_read	= mambo_nvram_start_read,
};
