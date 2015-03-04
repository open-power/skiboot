/* Copyright 2014-2015 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * imitations under the License.
 */

#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>
#include <err.h>
#include <poll.h>

#include <endian.h>

#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <linux/ipmi.h>
#include <linux/limits.h>

#include <asm/opal-prd.h>
#include <opal.h>

#include "hostboot-interface.h"
#include "pnor.h"
#include "i2c.h"

struct opal_prd_ctx {
	int			fd;
	int			socket;
	struct opal_prd_info	info;
	long			page_size;
	void			*code_addr;
	size_t			code_size;
	bool			debug;
	bool			allow_fsp_calls;
	struct pnor		pnor;
	char			*hbrt_file_name;
};

enum control_msg_type {
	CONTROL_MSG_ENABLE_OCCS		= 0x00,
	CONTROL_MSG_DISABLE_OCCS	= 0x01,
	CONTROL_MSG_TEMP_OCC_RESET	= 0x02,
	CONTROL_MSG_TEMP_OCC_ERROR	= 0x03,
};

struct control_msg {
	enum control_msg_type	type;
	uint64_t		response;
};

static struct opal_prd_ctx *ctx;

static const char *opal_prd_devnode = "/dev/opal-prd";
static const char *opal_prd_socket = "/run/opal-prd-control";
static const char *hbrt_code_region_name = "ibm,hbrt-code-image";
static const int opal_prd_version = 1;
static const uint64_t opal_prd_ipoll = 0xf000000000000000;

static const char *ipmi_devnode = "/dev/ipmi0";
static const int ipmi_timeout_ms = 2000;

/* Memory error handling */
static const char *mem_offline_soft =
		"/sys/devices/system/memory/soft_offline_page";
static const char *mem_offline_hard =
		"/sys/devices/system/memory/hard_offline_page";

#define ADDR_STRING_SZ 20 /* Hold %16lx */

/* This is the "real" HBRT call table for calling into HBRT as
 * provided by it. It will be used by the assembly thunk
 */
struct runtime_interfaces *hservice_runtime;
struct runtime_interfaces hservice_runtime_fixed;

/* This is the callback table provided by assembly code */
extern struct host_interfaces hinterface;

/* Create opd to call hostservice init */
struct func_desc {
	void *addr;
	void *toc;
} hbrt_entry;

static struct opal_prd_range *find_range(const char *name)
{
	struct opal_prd_range *range;
	unsigned int i;

	for (i = 0; i < OPAL_PRD_MAX_RANGES; i++) {
		range = &ctx->info.ranges[i];

		if (!strncmp(range->name, name, sizeof(range->name)))
			return range;
	}

	return NULL;
}

static void pr_debug(struct opal_prd_ctx *ctx, const char *fmt, ...)
{
	va_list ap;

	if (!ctx->debug)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/* HBRT init wrappers */
extern struct runtime_interfaces *call_hbrt_init(struct host_interfaces *);

/* hservice Call wrappers */

extern void call_cxxtestExecute(void *);
extern int call_handle_attns(uint64_t i_proc,
			uint64_t i_ipollStatus,
			uint64_t i_ipollMask);
extern void call_process_occ_error (uint64_t i_chipId);
extern int call_enable_attns(void);
extern int call_enable_occ_actuation(bool i_occActivation);
extern void call_process_occ_reset(uint64_t i_chipId);

/* Dummy calls for hservices */
static inline int __fsp_only_assert(const char *name)
{
	printf("error: %s is only implemented for FSP\n", name);
	if (!ctx->allow_fsp_calls)
		exit(EXIT_FAILURE);
	return 0;
}
#define fsp_stub(name) \
	int hservice_ ##name(void) { return __fsp_only_assert(#name); }

fsp_stub(send_error_log);
fsp_stub(lid_load);
fsp_stub(lid_unload);
fsp_stub(wakeup);
fsp_stub(report_occ_failure);

void hservice_puts(const char *str)
{
	printf("%s\n", str);
}

void hservice_assert(void)
{
	fprintf(stderr, "ERR: assert! exiting.\n");
	exit(EXIT_FAILURE);
}

void *hservice_malloc(size_t size)
{
	return malloc(size);
}

void hservice_free(void *ptr)
{
	free(ptr);
}

void *hservice_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

int hservice_scom_read(uint64_t chip_id, uint64_t addr, void *buf)
{
	int rc;
	struct opal_prd_scom scom;

	scom.chip = chip_id;
	scom.addr = addr;

	rc = ioctl(ctx->fd, OPAL_PRD_SCOM_READ, &scom);
	if (rc) {
		perror("ioctl scom_read");
		return 0;
	}

	pr_debug(ctx, "scom read: chip %lx addr %lx val %lx\n",
			chip_id, addr, scom.data);

	*(uint64_t *)buf = htobe64(scom.data);

	return 0;
}

int hservice_scom_write(uint64_t chip_id, uint64_t addr,
                               const void *buf)
{
	int rc;
	struct opal_prd_scom scom;

	scom.chip = chip_id;
	scom.addr = addr;
	scom.data = be64toh(*(uint64_t *)buf);

	rc = ioctl(ctx->fd, OPAL_PRD_SCOM_WRITE, &scom);
	if (rc) {
		perror("ioctl scom_write");
		return 0;
	}

	pr_debug(ctx, "scom write: chip %lx addr %lx val %lx\n",
			chip_id, addr, scom.data);

	return 0;
}

uint64_t hservice_get_reserved_mem(const char *name)
{
	uint64_t align_physaddr, offset;
	struct opal_prd_range *range;
	void *addr;

	pr_debug(ctx, "hservice_get_reserved_mem: %s\n", name);

	range = find_range(name);
	if (!range) {
		warnx("get_reserved_mem: no such range %s", name);
		return 0;
	}

	pr_debug(ctx, "Mapping 0x%016lx 0x%08lx %s\n",
			range->physaddr, range->size, range->name);

	align_physaddr = range->physaddr & ~(ctx->page_size-1);
	offset = range->physaddr & (ctx->page_size-1);
	addr = mmap(NULL, range->size, PROT_WRITE | PROT_READ,
				MAP_SHARED, ctx->fd, align_physaddr);

	if (addr == MAP_FAILED) {
		perror("mmap");
		return 0;
	}

	pr_debug(ctx, "hservice_get_reserved_mem: %s address %p\n", name, addr);
	if (addr)
		return (uint64_t)addr + offset;

	return 0;
}

void hservice_nanosleep(uint64_t i_seconds, uint64_t i_nano_seconds)
{
	const struct timespec ns = {
		.tv_sec = i_seconds,
		.tv_nsec = i_nano_seconds
	};

	nanosleep(&ns, NULL);
}

int hservice_set_page_execute(void *addr)
{
	pr_debug(ctx, "FIXME: hservice_set_page_execute(%p)\n", addr);
	return -1;
}

int hservice_clock_gettime(clockid_t i_clkId, struct timespec *o_tp)
{
	struct timespec tmp;
	int rc;

	rc = clock_gettime(i_clkId, &tmp);
	if (rc)
		return rc;

	o_tp->tv_sec = htobe64(tmp.tv_sec);
	o_tp->tv_nsec = htobe64(tmp.tv_nsec);

	return 0;
}

int hservice_pnor_read(uint32_t i_proc, const char* i_partitionName,
		uint64_t i_offset, void* o_data, size_t i_sizeBytes)
{
	return pnor_operation(&ctx->pnor, i_partitionName, i_offset, o_data,
			      i_sizeBytes, PNOR_OP_READ);
}

int hservice_pnor_write(uint32_t i_proc, const char* i_partitionName,
		uint64_t i_offset, void* o_data, size_t i_sizeBytes)
{
	return pnor_operation(&ctx->pnor, i_partitionName, i_offset, o_data,
			      i_sizeBytes, PNOR_OP_WRITE);
}

int hservice_i2c_read(uint64_t i_master, uint16_t i_devAddr,
		uint32_t i_offsetSize, uint32_t i_offset,
		uint32_t i_length, void* o_data)
{
	uint32_t chip_id;
	uint8_t engine, port;

	chip_id = (i_master & HBRT_I2C_MASTER_CHIP_MASK) >>
		HBRT_I2C_MASTER_CHIP_SHIFT;
	engine = (i_master & HBRT_I2C_MASTER_ENGINE_MASK) >>
		HBRT_I2C_MASTER_ENGINE_SHIFT;
	port = (i_master & HBRT_I2C_MASTER_PORT_MASK) >>
		HBRT_I2C_MASTER_PORT_SHIFT;
	return i2c_read(chip_id, engine, port, i_devAddr, i_offsetSize,
			i_offset, i_length, o_data);
}

int hservice_i2c_write(uint64_t i_master, uint16_t i_devAddr,
		uint32_t i_offsetSize, uint32_t i_offset,
		uint32_t i_length, void* i_data)
{
	uint32_t chip_id;
	uint8_t engine, port;

	chip_id = (i_master & HBRT_I2C_MASTER_CHIP_MASK) >>
		HBRT_I2C_MASTER_CHIP_SHIFT;
	engine = (i_master & HBRT_I2C_MASTER_ENGINE_MASK) >>
		HBRT_I2C_MASTER_ENGINE_SHIFT;
	port = (i_master & HBRT_I2C_MASTER_PORT_MASK) >>
		HBRT_I2C_MASTER_PORT_SHIFT;
	return i2c_write(chip_id, engine, port, i_devAddr, i_offsetSize,
			 i_offset, i_length, i_data);
}

static int ipmi_send(int fd, uint8_t netfn, uint8_t cmd, long seq,
		uint8_t *buf, size_t len)
{
	struct ipmi_system_interface_addr addr;
	struct ipmi_req req;
	int rc;

	memset(&addr, 0, sizeof(addr));
	addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	addr.channel = IPMI_BMC_CHANNEL;

	memset(&req, 0, sizeof(req));
	req.addr = (unsigned char *)&addr;
	req.addr_len = sizeof(addr);

	req.msgid = seq;
	req.msg.netfn = netfn;
	req.msg.cmd = cmd;
	req.msg.data = buf;
	req.msg.data_len = len;

	rc = ioctl(fd, IPMICTL_SEND_COMMAND, &req);
	if (rc < 0)
		return -1;

	return 0;
}

static int ipmi_recv(int fd, uint8_t *netfn, uint8_t *cmd, long *seq,
		uint8_t *buf, size_t *len)
{
	struct ipmi_recv recv;
	struct ipmi_addr addr;
	int rc;

	recv.addr = (unsigned char *)&addr;
	recv.addr_len = sizeof(addr);
	recv.msg.data = buf;
	recv.msg.data_len = *len;

	rc = ioctl(fd, IPMICTL_RECEIVE_MSG_TRUNC, &recv);
	if (rc < 0 && errno != EMSGSIZE) {
		warn("IPMI: recv (%zd bytes) failed: %m\n", *len);
		return -1;
	} else if (rc < 0 && errno == EMSGSIZE) {
		warn("IPMI: truncated message (netfn %d, cmd %d, "
				"size %zd), continuing anyway\n",
				recv.msg.netfn, recv.msg.cmd, *len);
	}

	*netfn = recv.msg.netfn;
	*cmd = recv.msg.cmd;
	*seq = recv.msgid;
	*len = recv.msg.data_len;

	return 0;
}

int hservice_ipmi_msg(uint8_t netfn, uint8_t cmd,
		void *tx_buf, size_t tx_size,
		void *rx_buf, size_t *rx_size)
{
	struct timeval start, now, delta;
	struct pollfd pollfds[1];
	static long seq;
	size_t size;
	int rc, fd;

	size = be64toh(*rx_size);

	fd = open(ipmi_devnode, O_RDWR);
	if (fd < 0) {
		warn("Failed to open IPMI device %s", ipmi_devnode);
		return -1;
	}

	seq++;
	pr_debug(ctx, "IPMI: sending %zd bytes (netfn 0x%02x, cmd 0x%02x)\n",
			tx_size, netfn, cmd);

	rc = ipmi_send(fd, netfn, cmd, seq, tx_buf, tx_size);
	if (rc) {
		warnx("IPMI: send failed");
		goto out;
	}

	gettimeofday(&start, NULL);

	pollfds[0].fd = fd;
	pollfds[0].events = POLLIN;

	for (;;) {
		long rx_seq;
		int timeout;

		gettimeofday(&now, NULL);
		timersub(&now, &start, &delta);
		timeout = ipmi_timeout_ms - ((delta.tv_sec * 1000) +
				(delta.tv_usec / 1000));
		if (timeout < 0)
			timeout = 0;

		rc = poll(pollfds, 1, timeout);
		if (rc < 0) {
			warn("poll(%s)", ipmi_devnode);
			break;
		}

		if (rc == 0) {
			warnx("IPMI response timeout");
			rc = -1;
			break;
		}

		rc = ipmi_recv(fd, &netfn, &cmd, &rx_seq, rx_buf, &size);
		if (rc)
			break;

		if (seq != rx_seq) {
			pr_debug(ctx, "IPMI: out-of-sequence reply: %ld, "
					"expected %ld. Dropping message.\n",
					rx_seq, seq);
			continue;
		}

		pr_debug(ctx, "IPMI: received %zd bytes\n", tx_size);
		*rx_size = be64toh(size);
		rc = 0;
		break;
	}

out:
	close(fd);
	return rc;
}

int hservice_memory_error(uint64_t i_start_addr, uint64_t i_endAddr,
		enum MemoryError_t i_errorType)
{
	char buf[ADDR_STRING_SZ];
	const char *sysfsfile;
	int memfd, rc, n;
	uint64_t addr;

	pr_debug(ctx, "Memory error addr:%016lx-%016lx type: %d\n",
			i_start_addr, i_endAddr, i_errorType);

	switch(i_errorType) {
	case MEMORY_ERROR_CE:
		sysfsfile = mem_offline_soft;
		break;
	case MEMORY_ERROR_UE:
		sysfsfile = mem_offline_hard;
		break;
	default:
		warn("Invalid memory error type %d", i_errorType);
		return -1;
	}

	memfd = open(sysfsfile, O_WRONLY);
	if (memfd < 0) {
		warn("Unable to open sysfs: %s", sysfsfile);
		return -1;
	}

	for (addr = i_start_addr; addr <= i_endAddr; addr += ctx->page_size) {
		n = snprintf(buf, ADDR_STRING_SZ, "0x%lx", addr);
		rc = write(memfd, buf, n);
		if (rc != n) {
			warn("Memory offine of addr: %016lx type: %d failed",
				addr, i_errorType);
			return rc;
		}
	}

	return 0;
}

void hservices_init(struct opal_prd_ctx *ctx, void *code)
{
	uint64_t *s, *d;
	int i, sz;

	pr_debug(ctx, "Code Address : [%p]\n", code);

	/* We enter at 0x100 into the image. */
	/* Load func desc in BE since we reverse it in thunk */

	hbrt_entry.addr = (void *)htobe64((unsigned long)code + 0x100);
	hbrt_entry.toc = 0; /* No toc for init entry point */

	if (memcmp(code, "HBRTVERS", 8) != 0)
		errx(EXIT_FAILURE, "HBRT: Bad signature for "
				"ibm,hbrt-code-image! exiting\n");

	pr_debug(ctx, "HBRT: calling ibm,hbrt_init() %p\n", hservice_runtime);
	hservice_runtime = call_hbrt_init(&hinterface);
	pr_debug(ctx, "HBRT: hbrt_init passed..... %p version %016lx\n",
			hservice_runtime, hservice_runtime->interface_version);

	sz = sizeof(struct runtime_interfaces)/sizeof(uint64_t);
	s = (uint64_t *)hservice_runtime;
	d = (uint64_t *)&hservice_runtime_fixed;
	/* Byte swap the function pointers */
	for (i = 0; i < sz; i++)
		d[i] = be64toh(s[i]);
}

static void fixup_hinterface_table(void)
{
	uint64_t *t64;
	unsigned int i, sz;

	/* Swap interface version */
	hinterface.interface_version =
		htobe64(hinterface.interface_version);

	/* Swap OPDs */
	sz = sizeof(struct host_interfaces) / sizeof(uint64_t);
	t64 = (uint64_t *)&hinterface;
	for (i = 1; i < sz; i++) {
		uint64_t *opd = (uint64_t *)t64[i];
		if (!opd)
			continue;
		t64[i] = htobe64(t64[i]);
		opd[0] = htobe64(opd[0]);
		opd[1] = htobe64(opd[1]);
		opd[2] = htobe64(opd[2]);
	}
}

static int map_hbrt_file(struct opal_prd_ctx *ctx, const char *name)
{
	struct stat statbuf;
	int fd, rc;
	void *buf;

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		warn("open(%s)", name);
		return -1;
	}

	rc = fstat(fd, &statbuf);
	if (rc < 0) {
		warn("fstat(%s)", name);
		close(fd);
		return -1;
	}

	buf = mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE, fd, 0);
	close(fd);

	if (buf == MAP_FAILED) {
		warn("mmap(%s)", name);
		return -1;
	}

	ctx->code_addr = buf;
	ctx->code_size = statbuf.st_size;
	return -0;
}

static int map_hbrt_physmem(struct opal_prd_ctx *ctx, const char *name)
{
	struct opal_prd_range *range;
	void *buf;

	range = find_range(name);
	if (!range) {
		warnx("can't find code region %s\n", name);
		return -1;
	}

	buf = mmap(NULL, range->size, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE, ctx->fd, range->physaddr);
	if (buf == MAP_FAILED) {
		warn("mmap(range:%s)\n", name);
		return -1;
	}

	ctx->code_addr = buf;
	ctx->code_size = range->size;
	return 0;
}

static void dump_hbrt_map(struct opal_prd_ctx *ctx)
{
	const char *dump_name = "hbrt.bin";
	int fd, rc;

	if (!ctx->debug)
		return;

	fd = open(dump_name, O_WRONLY | O_CREAT, 0644);
	if (fd < 0)
		err(EXIT_FAILURE, "couldn't open %s for writing", dump_name);

	ftruncate(fd, 0);
	rc = write(fd, ctx->code_addr, ctx->code_size);
	close(fd);

	if (rc != ctx->code_size)
		warn("write to %s failed", dump_name);
	else
		pr_debug(ctx, "dumped HBRT binary to %s\n", dump_name);
}

static int prd_init(struct opal_prd_ctx *ctx)
{
	int rc;

	ctx->page_size = sysconf(_SC_PAGE_SIZE);

	/* set up the device, and do our get_info ioctl */
	ctx->fd = open(opal_prd_devnode, O_RDWR);
	if (ctx->fd < 0) {
		warn("Can't open PRD device %s\n", opal_prd_devnode);
		return -1;
	}

	rc = ioctl(ctx->fd, OPAL_PRD_GET_INFO, &ctx->info);
	if (rc) {
		warn("Can't get PRD info");
		return -1;
	}

	return 0;
}

static int handle_msg_attn(struct opal_prd_ctx *ctx, struct opal_prd_msg *msg)
{
	uint64_t proc, ipoll_mask, ipoll_status;
	int rc;

	proc = be64toh(msg->attn.proc);
	ipoll_status = be64toh(msg->attn.ipoll_status);
	ipoll_mask = be64toh(msg->attn.ipoll_mask);

	if (!hservice_runtime->handle_attns) {
		fprintf(stderr, "no handle_attns call\n");
		return -1;
	}

	rc = call_handle_attns(proc, ipoll_status, ipoll_mask);
	if (rc) {
		fprintf(stderr, "enable_attns(%lx,%lx,%lx) failed, rc %d",
				proc, ipoll_status, ipoll_mask, rc);
		return -1;
	}

	/* send the response */
	msg->type = OPAL_PRD_MSG_TYPE_ATTN_ACK;
	msg->attn_ack.proc = htobe64(proc);
	msg->attn_ack.ipoll_ack = htobe64(ipoll_status);
	rc = write(ctx->fd, msg, sizeof(*msg));

	if (rc != sizeof(*msg)) {
		warn("write(ATTN_ACK) failed");
		return -1;
	}

	return 0;
}

static int handle_msg_occ_error(struct opal_prd_ctx *ctx,
		struct opal_prd_msg *msg)
{
	uint32_t proc;

	proc = be64toh(msg->occ_error.chip);

	if (!hservice_runtime->process_occ_error) {
		fprintf(stderr, "no process_occ_error call\n");
		return -1;
	}

	call_process_occ_error(proc);
	return 0;
}

static int handle_msg_occ_reset(struct opal_prd_ctx *ctx,
		struct opal_prd_msg *msg)
{
	uint32_t proc;

	proc = be64toh(msg->occ_reset.chip);

	if (!hservice_runtime->process_occ_reset) {
		fprintf(stderr, "no handle_reset call\n");
		return -1;
	}

	call_process_occ_reset(proc);
	return 0;
}

static int handle_prd_msg(struct opal_prd_ctx *ctx)
{
	struct opal_prd_msg msg;
	int rc;

	rc = read(ctx->fd, &msg, sizeof(msg));
	if (rc < 0 && errno == EAGAIN)
		return -1;

	if (rc != sizeof(msg)) {
		warn("read on opal prd device failed");
		return -1;
	}

	switch (msg.type) {
	case OPAL_PRD_MSG_TYPE_ATTN:
		rc = handle_msg_attn(ctx, &msg);
		break;
	case OPAL_PRD_MSG_TYPE_OCC_RESET:
		rc = handle_msg_occ_reset(ctx, &msg);
		break;
	case OPAL_PRD_MSG_TYPE_OCC_ERROR:
		rc = handle_msg_occ_error(ctx, &msg);
		break;
	default:
		warn("Invalid incoming message type 0x%x\n", msg.type);
		return -1;
	}

	return 0;
}

static int handle_prd_control(struct opal_prd_ctx *ctx, int fd)
{
	struct control_msg msg;
	bool enabled;
	int rc;

	rc = recv(fd, &msg, sizeof(msg), MSG_TRUNC);
	if (rc != sizeof(msg)) {
		warn("recvfrom");
		return -1;
	}

	enabled = false;
	rc = -1;

	switch (msg.type) {
	case CONTROL_MSG_ENABLE_OCCS:
		enabled = true;
		/* fall through */
	case CONTROL_MSG_DISABLE_OCCS:
		if (!hservice_runtime->enable_occ_actuation) {
			fprintf(stderr, "no enable_occ_actuation call\n");
		} else {
			pr_debug(ctx, "calling enable_occ_actuation(%s)\n",
					enabled ? "true" : "false");
			rc = call_enable_occ_actuation(enabled);
			pr_debug(ctx, " -> %d\n", rc);
		}
		break;
	case CONTROL_MSG_TEMP_OCC_RESET:
		if (hservice_runtime->process_occ_reset) {
			pr_debug(ctx, "calling process_occ_reset(0)\n");
			call_process_occ_reset(0);
			rc = 0;
		} else {
			fprintf(stderr, "no process_occ_reset call\n");
		}
		break;
	case CONTROL_MSG_TEMP_OCC_ERROR:
		if (hservice_runtime->process_occ_error) {
			pr_debug(ctx, "calling process_occ_error(0)\n");
			call_process_occ_error(0);
			rc = 0;
		} else {
			fprintf(stderr, "no process_occ_error call\n");
		}
		break;
	default:
		fprintf(stderr, "Unknown control message action %d",
				msg.type);
	}

	/* send a response */
	msg.response = rc;
	rc = send(fd, &msg, sizeof(msg), MSG_DONTWAIT | MSG_NOSIGNAL);
	if (rc && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EPIPE))
		pr_debug(ctx, "control send() returned %d, ignoring failure\n",
				rc);
	else if (rc != sizeof(msg))
		warn("control socket send failed");

	return 0;
}

static int run_attn_loop(struct opal_prd_ctx *ctx)
{
	struct pollfd pollfds[2];
	struct opal_prd_msg msg;
	int rc, fd;

	if (hservice_runtime->enable_attns) {
		pr_debug(ctx, "calling enable_attns()\n");
		rc = call_enable_attns();
		if (rc) {
			fprintf(stderr, "enable_attns() failed, aborting\n");
			return -1;
		}
	}

	/* send init message, to unmask interrupts */
	msg.type = OPAL_PRD_MSG_TYPE_INIT;
	msg.init.version = htobe64(opal_prd_version);
	msg.init.ipoll = htobe64(opal_prd_ipoll);

	pr_debug(ctx, "writing init message\n");
	rc = write(ctx->fd, &msg, sizeof(msg));
	if (rc != sizeof(msg)) {
		warn("init message failed, aborting");
		return -1;
	}

	pollfds[0].fd = ctx->fd;
	pollfds[0].events = POLLIN | POLLERR;
	pollfds[1].fd = ctx->socket;
	pollfds[1].events = POLLIN | POLLERR;

	for (;;) {
		rc = poll(pollfds, 2, -1);
		if (rc < 0)
			err(EXIT_FAILURE, "poll");

		if (!rc)
			continue;

		if (pollfds[0].revents & POLLIN)
			handle_prd_msg(ctx);

		if (pollfds[1].revents & POLLIN) {
			fd = accept(ctx->socket, NULL, NULL);
			if (fd < 0) {
				warn("accept");
				continue;
			}
			handle_prd_control(ctx, fd);
			close(fd);
		}
	}

	return 0;
}

static int init_control_socket(struct opal_prd_ctx *ctx)
{
	struct sockaddr_un addr;
	int fd, rc;

	unlink(opal_prd_socket);

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, opal_prd_socket);

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		warn("Can't open control socket %s", opal_prd_socket);
		return -1;
	}

	rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc) {
		warn("Can't bind control socket %s", opal_prd_socket);
		close(fd);
		return -1;
	}

	rc = listen(fd, 0);
	if (rc) {
		warn("Can't listen on control socket %s", opal_prd_socket);
		close(fd);
		return -1;
	}

	ctx->socket = fd;
	return 0;
}

static int run_prd_daemon(struct opal_prd_ctx *ctx)
{
	int rc;

	ctx->fd = -1;
	ctx->socket = -1;

	i2c_init();

#ifdef DEBUG_I2C
	{
		uint8_t foo[128];
		int i;

		rc = i2c_read(0, 1, 2, 0x50, 2, 0x10, 128, foo);
		printf("read rc: %d\n", rc);
		for (i = 0; i < sizeof(foo); i += 8) {
			printf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
			       foo[i + 0], foo[i + 1], foo[i + 2], foo[i + 3],
			       foo[i + 4], foo[i + 5], foo[i + 6], foo[i + 7]);
		}
	}
#endif
	rc = init_control_socket(ctx);
	if (rc) {
		warnx("Error initialising PRD control");
		goto out_close;
	}


	rc = prd_init(ctx);
	if (rc) {
		warnx("Error initialising PRD setup");
		goto out_close;
	}


	if (ctx->hbrt_file_name) {
		rc = map_hbrt_file(ctx, ctx->hbrt_file_name);
		if (rc) {
			warnx("can't access hbrt file %s", ctx->hbrt_file_name);
			goto out_close;
		}
	} else {
		rc = map_hbrt_physmem(ctx, hbrt_code_region_name);
		if (rc) {
			warn("can't access hbrt physical memory");
			goto out_close;
		}
		dump_hbrt_map(ctx);
	}

	pr_debug(ctx, "hbrt map at %p, size 0x%zx\n",
			ctx->code_addr, ctx->code_size);

	fixup_hinterface_table();

	pr_debug(ctx, "calling hservices_init\n");
	hservices_init(ctx, ctx->code_addr);
	pr_debug(ctx, "hservices_init done\n");

	if (ctx->pnor.path) {
		rc = pnor_init(&ctx->pnor);
		if (rc) {
			printf("Failed to open pnor\n");
			goto out_close;
		}
	}

	/* Test a scom */
	if (ctx->debug) {
		uint64_t val;
		printf("trying scom read\n");
		fflush(stdout);
		hservice_scom_read(0x00, 0xf000f, &val);
		printf("f00f: %lx\n", be64toh(val));
	}

	run_attn_loop(ctx);
	rc = 0;

out_close:
	pnor_close(&ctx->pnor);
	if (ctx->fd != -1)
		close(ctx->fd);
	if (ctx->socket != -1)
		close(ctx->socket);
	return rc;
}

static int send_occ_control(struct opal_prd_ctx *ctx, const char *str)
{
	struct sockaddr_un addr;
	struct control_msg msg;
	int sd, rc;

	memset(&msg, 0, sizeof(msg));

	if (!strcmp(str, "enable")) {
		msg.type = CONTROL_MSG_ENABLE_OCCS;
	} else if (!strcmp(str, "disable")) {
		msg.type = CONTROL_MSG_DISABLE_OCCS;
	} else if (!strcmp(str, "reset")) {
		msg.type = CONTROL_MSG_TEMP_OCC_RESET;
	} else if (!strcmp(str, "process-error")) {
		msg.type = CONTROL_MSG_TEMP_OCC_ERROR;
	} else {
		fprintf(stderr, "Invalid OCC action '%s'\n", str);
		return -1;
	}

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (!sd) {
		warn("Failed to create control socket");
		return -1;
	}

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, opal_prd_socket);

	rc = connect(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc) {
		warn("Failed to connect to prd daemon");
		goto out_close;
	}

	rc = send(sd, &msg, sizeof(msg), 0);
	if (rc != sizeof(msg)) {
		warn("send");
		rc = -1;
		goto out_close;
	}

	/* wait for our reply */
	rc = recv(sd, &msg, sizeof(msg), 0);
	if (rc < 0) {
		warn("control socket receive failed");
		goto out_close;

	} else if (rc != sizeof(msg)) {
		warnx("short read from control socket");
		rc = -1;
		goto out_close;
	}

	if (msg.response || ctx->debug) {
		warnx("OCC action %s returned status %ld\n",
				str, msg.response);
	}

	rc = msg.response;

out_close:
	close(sd);
	return rc;
}

static void usage(const char *progname)
{
	printf("Usage:\n");
	printf("\t%s [--debug] [--file <hbrt-image>] [--pnor <device>]\n"
			"\t\t[--allow-fsp-calls]\n",
			progname);
	printf("\t%s occ <enable|disable>\n", progname);
	printf("\n");
	printf("Options:\n"
"\t--debug            verbose logging for debug information\n"
"\t--pnor DEVICE      use PNOR MTD device\n"
"\t--file FILE        use FILE for hostboot runtime code (instead of code\n"
"\t                     exported by firmware)\n"
"\t--allow-fsp-calls  don't exit on FSP-only callbacks from HBRT code, but\n"
"\t                     return success instead. Intended for workarounds\n"
"\t                     during PRD testing only.\n");
}

static struct option opal_diag_options[] = {
	{"file", required_argument, NULL, 'f'},
	{"pnor", required_argument, NULL, 'p'},
	{"debug", no_argument, NULL, 'd'},
	{"allow-fsp-calls", no_argument, NULL, 'a'},
	{"help", no_argument, NULL, 'h'},
	{ 0 },
};

enum action {
	ACTION_RUN_DAEMON,
	ACTION_OCC_CONTROL,
};

static int parse_action(const char *str, enum action *action)
{
	if (!strcmp(str, "occ")) {
		*action = ACTION_OCC_CONTROL;
		return 0;
	}

	if (!strcmp(str, "daemon")) {
		*action = ACTION_RUN_DAEMON;
		return 0;
	}

	fprintf(stderr, "unknown argument '%s'\n", str);
	return -1;
}

int main(int argc, char *argv[])
{
	struct opal_prd_ctx _ctx;
	enum action action;
	int rc;

	ctx = &_ctx;
	memset(ctx, 0, sizeof(*ctx));

	/* Parse options */
	for (;;) {
		int c;

		c = getopt_long(argc, argv, "f:p:dh", opal_diag_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'f':
			ctx->hbrt_file_name = optarg;
			break;
		case 'd':
			ctx->debug = true;
			break;
		case 'p':
			ctx->pnor.path = strndup(optarg, PATH_MAX);
			break;
		case 'a':
			ctx->allow_fsp_calls = true;
			break;
		case 'h':
			usage(argv[0]);
			return EXIT_SUCCESS;
		case '?':
		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (optind < argc) {
		rc = parse_action(argv[optind], &action);
		if (rc)
			return EXIT_FAILURE;
	} else {
		action = ACTION_RUN_DAEMON;
	}

	if (action == ACTION_RUN_DAEMON) {
		rc = run_prd_daemon(ctx);

	} else if (action == ACTION_OCC_CONTROL) {

		if (optind + 1 >= argc) {
			fprintf(stderr, "occ command requires an argument\n");
			return EXIT_FAILURE;
		}

		rc = send_occ_control(ctx, argv[optind + 1]);
	}

	return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

