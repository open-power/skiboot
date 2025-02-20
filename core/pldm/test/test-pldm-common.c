// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2024 IBM Corp.

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#define HAVE_LITTLE_ENDIAN 1
#include <stdbool.h>
#include <types.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <timer.h>
#include <pthread.h>

#define __LITTLE_ENDIAN_BITFIELD
#define __TEST__
#define __SKIBOOT__
#define zalloc(bytes) calloc(1, (bytes))
static inline unsigned long mftb(void);
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <timebase.h>
#include <op-panel.h>
#include <core/pldm/pldm.h>
#include <include/platform.h>
#include <include/pldm.h>
#include <ast.h>
#ifdef ARRAY_SIZE
#undef ARRAY_SIZE
#endif

#define MCTP_DEFAULT_ALLOC 1

#include <pldm/include/libpldm/bios_table.h>
#include <pldm/libpldm/bios_table.c>
#undef pr_fmt
#undef pr_fmt
#define HAVE_CONFIG_H 1
#include <libmctp/libmctp-alloc.h>
#undef pr_fmt
#include <libmctp/libmctp-astlpc.h>
#undef pr_fmt
#include "../pldm-bios-requests.c"
#include "../pldm-lid-files.c"
#include <pldm/libpldm/base.c>
#include <pldm/libpldm/pdr.c>
#include <pldm/libpldm/bios.c>
#include <pldm/libpldm/platform.c>
#include <pldm/libpldm/utils.c>
#include <pldm/libpldm/oem/ibm/file_io.c>
#include <pldm/libpldm/fru.c>
#include <libmctp/crc32.c>
#include "../pldm-file-io-requests.c"
#include "../pldm-requester.c"
#include "../pldm-mctp.c"
#include "../pldm-responder.c"
#include "../pldm-base-requests.c"
#include "../pldm-watchdog.c"
#include "../pldm-fru-requests.c"
#include "../pldm-platform-requests.c"
#include "../../device.c"

pthread_t pid;

void *polling_func(void *data) __noreturn;


char __rodata_start[1], __rodata_end[1];
unsigned long tb_hz = 512000000;
struct dt_node *dt_root;
struct debug_descriptor debug_descriptor;
struct platform platform;

int ast_mctp_ready(void)
{
	return OPAL_SUCCESS;
}

void time_wait_ms(unsigned long ms)
{
	usleep(ms * 1000);
}

static void call_timer_expiry_func(union sigval timer_data)
{
	struct timer *t = (struct timer *) timer_data.sival_ptr;

	t->expiry(t, t->user_data, clock());
}

void init_timer(struct timer *t, timer_func_t expiry, void *data)
{
	int rc;
	struct sigevent sevp = {0};

	t->target = 0;
	t->expiry = expiry;
	t->user_data = data;
	t->running = NULL;
	t->link.next = t->link.prev = NULL;

	sevp.sigev_notify = SIGEV_THREAD;
	sevp.sigev_value.sival_ptr = t;
	sevp.sigev_notify_function = call_timer_expiry_func;

	rc = timer_create(CLOCK_REALTIME, &sevp, (timer_t *)&t->target);
	if (rc != 0)
		printf("%s: Error Creating timer\n", __func__);
}

uint64_t schedule_timer(struct timer *t, uint64_t how_long)
{
	int rc;
	// Interval time in milliseconds
	uint64_t interval_time = (how_long * 1000) / tb_hz;

	struct itimerspec its = {
		.it_value.tv_sec  = interval_time / 1000,
		.it_value.tv_nsec = (interval_time % 1000) * 1000000,
		.it_interval.tv_sec  = 0,
		.it_interval.tv_nsec = 0
	};
	/* Start Timer */
	rc = timer_settime((timer_t)t->target, 0, &its, NULL);
	if (rc != 0) {
		printf("%s: Error setting timer ::rc=%d\n", __func__);
		perror("timer_settime");
		return rc;
	}

	return OPAL_SUCCESS;
}

void cancel_timer(struct timer *t)
{
	t->link.next = t->link.prev = NULL;
	timer_delete((timer_t)t->target);
}

static inline unsigned long mftb(void)
{
	unsigned long clk;

	clk = clock();
	return clk;
}

int ast_mctp_init(void)
{
	return OPAL_PARAMETER;
}

void ast_mctp_exit(void) {}

void lock_caller(struct lock *l, const char *caller)
{
	(void)caller;
	pthread_mutex_lock((pthread_mutex_t *)l);
}


void unlock(struct lock *l)
{
	pthread_mutex_unlock((pthread_mutex_t *)l);
}

int _opal_queue_msg(enum opal_msg_type msg_type __unused, void *data __unused,
		void (*consumed)(void *data, int status) __unused,
		size_t params_size __unused, const void *params __unused)
{
	return OPAL_PARAMETER;

}

struct polling_data {
	void (*poll_func)(void *data);
	void *args;
};

void *polling_func(void *data)
{
	struct polling_data pd, *ppd;

	ppd = (struct polling_data *)data;
	pd.poll_func = ppd->poll_func;
	pd.args = ppd->args;
	free(data);

	while (1) {
		time_wait_ms(100);
		pd.poll_func(pd.args);
	}
}

void opal_add_poller(void (*poller)(void *data), void *data)
{
	struct polling_data *pd;
	pthread_attr_t tattr;

	pd = malloc(sizeof(struct polling_data));
	pd->poll_func = poller;
	pd->args = data;

	pthread_attr_init(&tattr);
	pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_JOINABLE);

	pthread_create(&pid, &tattr, &polling_func, (void *)pd);
}

void kill_poller(void)
{
	pthread_cancel(pid);
	pthread_join(pid, NULL);
}


void prd_occ_reset(uint32_t proc)
{
	(void)proc;

}
