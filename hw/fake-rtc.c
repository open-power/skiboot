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
#include <mem_region.h>

static uint32_t *fake_ymd;
static uint64_t *fake_hmsm;

static int64_t fake_rtc_write(uint32_t ymd, uint64_t hmsm)
{
	*fake_ymd = ymd;
	*fake_hmsm = hmsm;

	return OPAL_SUCCESS;
}

static int64_t fake_rtc_read(uint32_t *ymd, uint64_t *hmsm)
{
	if (!ymd || !hmsm)
		return OPAL_PARAMETER;

	*ymd = *fake_ymd;
	*hmsm = *fake_hmsm;

	return OPAL_SUCCESS;
}

void fake_rtc_init(void)
{
	struct mem_region *rtc_region = NULL;
	uint32_t *rtc = NULL;

	/* Read initial values from reserved memory */
	rtc_region = find_mem_region("ibm,fake-rtc");

	/* Should we register anyway? */
	if (!rtc_region) {
		prlog(PR_TRACE, "No initial RTC value found\n");
		return;
	}

	rtc = (uint32_t *) rtc_region->start;

	fake_ymd = rtc;
	fake_hmsm = ((uint64_t *) &rtc[1]);

	prlog(PR_TRACE, "Init fake RTC to 0x%x 0x%llx\n",
	      *fake_ymd, *fake_hmsm);

	opal_register(OPAL_RTC_READ, fake_rtc_read, 2);
	opal_register(OPAL_RTC_WRITE, fake_rtc_write, 2);
}
