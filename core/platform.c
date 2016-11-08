/* Copyright 2013-2016 IBM Corp.
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
#include <chip.h>
#include <xscom.h>
#include <errorlog.h>
#include <bt.h>
#include <nvram.h>

bool manufacturing_mode = false;
struct platform	platform;
const struct bmc_platform *bmc_platform = NULL;

DEFINE_LOG_ENTRY(OPAL_RC_ABNORMAL_REBOOT, OPAL_PLATFORM_ERR_EVT, OPAL_CEC,
		 OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_REBOOT,
		 OPAL_ABNORMAL_POWER_OFF);

/*
 * Various wrappers for platform functions
 */
static int64_t opal_cec_power_down(uint64_t request)
{
	prlog(PR_NOTICE, "OPAL: Shutdown request type 0x%llx...\n", request);

	console_complete_flush();

	if (platform.cec_power_down)
		return platform.cec_power_down(request);

	return OPAL_SUCCESS;
}
opal_call(OPAL_CEC_POWER_DOWN, opal_cec_power_down, 1);

static int64_t opal_cec_reboot(void)
{
	prlog(PR_NOTICE, "OPAL: Reboot request...\n");

	console_complete_flush();

	/* Try a fast reset first, if enabled */
	if (nvram_query_eq("experimental-fast-reset","feeling-lucky"))
		fast_reboot();

	if (platform.cec_reboot)
		return platform.cec_reboot();

	return OPAL_SUCCESS;
}
opal_call(OPAL_CEC_REBOOT, opal_cec_reboot, 0);

static int64_t opal_cec_reboot2(uint32_t reboot_type, char *diag)
{
	struct errorlog *buf;

	switch (reboot_type) {
	case OPAL_REBOOT_NORMAL:
		return opal_cec_reboot();
	case OPAL_REBOOT_PLATFORM_ERROR:
		prlog(PR_EMERG,
			  "OPAL: Reboot requested due to Platform error.");
		buf = opal_elog_create(&e_info(OPAL_RC_ABNORMAL_REBOOT), 0);
		if (buf) {
			log_append_msg(buf,
			  "OPAL: Reboot requested due to Platform error.");
			if (diag) {
				/* Add user section "DESC" */
				log_add_section(buf, 0x44455350);
				log_append_data(buf, diag, strlen(diag));
				log_commit(buf);
			}
		} else {
			prerror("OPAL: failed to log an error\n");
		}
		disable_fast_reboot("Reboot due to Platform Error");
		return xscom_trigger_xstop();
	default:
		prlog(PR_NOTICE, "OPAL: Unsupported reboot request %d\n", reboot_type);
		return OPAL_UNSUPPORTED;
		break;
	}
	return OPAL_SUCCESS;
}
opal_call(OPAL_CEC_REBOOT2, opal_cec_reboot2, 2);

static void generic_platform_init(void)
{
	/* Enable a UART if we find one in the device-tree */
	uart_init();

	if (uart_enabled())
		uart_setup_opal_console();
	else
		force_dummy_console();

	/* Enable a BT interface if we find one too */
	bt_init();

	/* Fake a real time clock */
	fake_rtc_init();
}

static int64_t generic_cec_power_down(uint64_t request __unused)
{
	return OPAL_UNSUPPORTED;
}

static struct bmc_platform generic_bmc = {
	.name = "generic",
};

static struct platform generic_platform = {
	.name		= "generic",
	.bmc		= &generic_bmc,
	.init		= generic_platform_init,
	.cec_power_down	= generic_cec_power_down,
};

void set_bmc_platform(const struct bmc_platform *bmc)
{
	if (bmc)
		prlog(PR_NOTICE, "PLAT: Detected BMC platform %s\n", bmc->name);
	bmc_platform = bmc;
}

void probe_platform(void)
{
	struct platform *platforms = &__platforms_start;
	unsigned int i;

	/* Detect Manufacturing mode */
	if (dt_find_property(dt_root, "ibm,manufacturing-mode")) {
		/**
		 * @fwts-label ManufacturingMode
		 * @fwts-advice You are running in manufacturing mode.
		 * This mode should only be enabled in a factory during
		 * manufacturing.
		 */
		prlog(PR_NOTICE, "PLAT: Manufacturing mode ON\n");
		manufacturing_mode = true;
	}

	platform = generic_platform;
	for (i = 0; &platforms[i] < &__platforms_end; i++) {
		if (platforms[i].probe && platforms[i].probe()) {
			platform = platforms[i];
			break;
		}
	}

	prlog(PR_NOTICE, "PLAT: Detected %s platform\n", platform.name);

	set_bmc_platform(platform.bmc);
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
	int waited = 0;

	while(r == OPAL_BUSY) {
		opal_run_pollers();
		time_wait_ms_nopoll(5);
		waited+=5;
		r = resource_loaded(id, idx);
	}

	prlog(PR_TRACE, "PLATFORM: wait_for_resource_loaded %x/%x %u ms\n",
	      id, idx, waited);
	return r;
}
