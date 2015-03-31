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
#include <console.h>
#include <timebase.h>
#include <cpu.h>

struct platform	platform;

/*
 * Various wrappers for platform functions
 */
static int64_t opal_cec_power_down(uint64_t request)
{
	printf("OPAL: Shutdown request type 0x%llx...\n", request);

	if (platform.cec_power_down)
		return platform.cec_power_down(request);

	return OPAL_SUCCESS;
}
opal_call(OPAL_CEC_POWER_DOWN, opal_cec_power_down, 1);

static int64_t opal_cec_reboot(void)
{
	printf("OPAL: Reboot request...\n");

#ifdef ENABLE_FAST_RESET
	/* Try a fast reset first */
	fast_reset();
#endif
	if (platform.cec_reboot)
		return platform.cec_reboot();

	return OPAL_SUCCESS;
}
opal_call(OPAL_CEC_REBOOT, opal_cec_reboot, 0);

static void generic_platform_init(void)
{
	force_dummy_console();
	fake_rtc_init();
}

static struct platform generic_platform = {
	.name	= "generic",
	.init	= generic_platform_init,
};

void probe_platform(void)
{
	struct platform *platforms = &__platforms_start;
	unsigned int i;

	platform = generic_platform;

	for (i = 0; &platforms[i] < &__platforms_end; i++) {
		if (platforms[i].probe && platforms[i].probe()) {
			platform = platforms[i];
			break;
		}
	}

	printf("PLAT: Detected %s platform\n", platform.name);
}

int start_preload_resource(enum resource_id id, uint32_t subid,
			   void *buf, size_t *len)
{
	if (!platform.start_preload_resource)
		return OPAL_UNSUPPORTED;

	return platform.start_preload_resource(id, subid, buf, len);
}

int resource_loaded(enum resource_id id, uint32_t idx)
{
	if (!platform.resource_loaded)
		return OPAL_SUCCESS;

	return platform.resource_loaded(id, idx);
}

int wait_for_resource_loaded(enum resource_id id, uint32_t idx)
{
	int r = resource_loaded(id, idx);

	while(r == OPAL_BUSY) {
		opal_run_pollers();
		time_wait_ms_nopoll(5);
		r = resource_loaded(id, idx);
	}

	return r;
}
