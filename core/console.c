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

/*
 * Console IO routine for use by libc
 *
 * fd is the classic posix 0,1,2 (stdin, stdout, stderr)
 */
#include <skiboot.h>
#include <unistd.h>
#include <console.h>
#include <opal.h>
#include <device.h>
#include <processor.h>
#include <cpu.h>

static char *con_buf = (char *)INMEM_CON_START;
static size_t con_in;
static size_t con_out;
static bool con_wrapped;
static struct con_ops *con_driver;

struct lock con_lock = LOCK_UNLOCKED;

/* This is mapped via TCEs so we keep it alone in a page */
struct memcons memcons __section(".data.memcons") = {
	.magic		= MEMCONS_MAGIC,
	.obuf_phys	= INMEM_CON_START,
	.ibuf_phys	= INMEM_CON_START + INMEM_CON_OUT_LEN,
	.obuf_size	= INMEM_CON_OUT_LEN,
	.ibuf_size	= INMEM_CON_IN_LEN,
};

bool dummy_console_enabled(void)
{
#ifdef FORCE_DUMMY_CONSOLE
	return true;
#else
	return dt_has_node_property(dt_chosen,
				    "sapphire,enable-dummy-console", NULL);
#endif
}

void force_dummy_console(void)
{
	dt_add_property(dt_chosen, "sapphire,enable-dummy-console", NULL, 0);
}

#ifdef MAMBO_CONSOLE
static void mambo_write(const char *buf, size_t count)
{
#define SIM_WRITE_CONSOLE_CODE	0
	register int c asm("r3") = 0; /* SIM_WRITE_CONSOLE_CODE */
	register unsigned long a1 asm("r4") = (unsigned long)buf;
	register unsigned long a2 asm("r5") = count;
	register unsigned long a3 asm("r6") = 0;
	asm volatile (".long 0x000eaeb0":"=r" (c):"r"(c), "r"(a1), "r"(a2),
		      "r"(a3));
}
#else
static void mambo_write(const char *buf __unused, size_t count __unused) { }
#endif /* MAMBO_CONSOLE */

void clear_console(void)
{
	memset(con_buf, 0, INMEM_CON_LEN);
}

/*
 * Flush the console buffer into the driver, returns true
 * if there is more to go
 */
bool __flush_console(void)
{
	struct cpu_thread *cpu = this_cpu();
	size_t req, len = 0;
	static bool in_flush, more_flush;

	/* Is there anything to flush ? Bail out early if not */
	if (con_in == con_out || !con_driver)
		return false;

	/*
	 * Console flushing is suspended on this CPU, typically because
	 * some critical locks are held that would potentially case a
	 * flush to deadlock
	 */
	if (cpu->con_suspend) {
		cpu->con_need_flush = true;
		return false;
	}
	cpu->con_need_flush = false;

	/*
	 * We must call the underlying driver with the console lock
	 * dropped otherwise we get some deadlocks if anything down
	 * that path tries to printf() something.
	 *
	 * So instead what we do is we keep a static in_flush flag
	 * set/released with the lock held, which is used to prevent
	 * concurrent attempts at flushing the same chunk of buffer
	 * by other processors.
	 */
	if (in_flush) {
		more_flush = true;
		return false;
	}
	in_flush = true;

	do {
		more_flush = false;
		if (con_out > con_in) {
			req = INMEM_CON_OUT_LEN - con_out;
			unlock(&con_lock);
			len = con_driver->write(con_buf + con_out, req);
			lock(&con_lock);
			con_out = (con_out + len) % INMEM_CON_OUT_LEN;
			if (len < req)
				goto bail;
		}
		if (con_out < con_in) {
			unlock(&con_lock);
			len = con_driver->write(con_buf + con_out,
						con_in - con_out);
			lock(&con_lock);
			con_out = (con_out + len) % INMEM_CON_OUT_LEN;
		}
	} while(more_flush);
bail:
	in_flush = false;
	return con_out != con_in;
}

bool flush_console(void)
{
	bool ret;

	lock(&con_lock);
	ret = __flush_console();
	unlock(&con_lock);

	return ret;
}

static void inmem_write(char c)
{
	uint32_t opos;

	if (!c)
		return;
	con_buf[con_in++] = c;
	if (con_in >= INMEM_CON_OUT_LEN) {
		con_in = 0;
		con_wrapped = true;
	}

	/*
	 * We must always re-generate memcons.out_pos because
	 * under some circumstances, the console script will
	 * use a broken putmemproc that does RMW on the full
	 * 8 bytes containing out_pos and in_prod, thus corrupting
	 * out_pos
	 */
	opos = con_in;
	if (con_wrapped)
		opos |= MEMCONS_OUT_POS_WRAP;
	lwsync();
	memcons.out_pos = opos;

	/* If head reaches tail, push tail around & drop chars */
	if (con_in == con_out)
		con_out = (con_in + 1) % INMEM_CON_OUT_LEN;
}

static size_t inmem_read(char *buf, size_t req)
{
	size_t read = 0;
	char *ibuf = (char *)memcons.ibuf_phys;

	while (req && memcons.in_prod != memcons.in_cons) {
		*(buf++) = ibuf[memcons.in_cons];
		lwsync();
		memcons.in_cons = (memcons.in_cons + 1) % INMEM_CON_IN_LEN;
		req--;
		read++;
	}
	return read;
}

static void write_char(char c)
{
	mambo_write(&c, 1);
	inmem_write(c);
}

ssize_t write(int fd __unused, const void *buf, size_t count)
{
	/* We use recursive locking here as we can get called
	 * from fairly deep debug path
	 */
	bool need_unlock = lock_recursive(&con_lock);
	const char *cbuf = buf;

	while(count--) {
		char c = *(cbuf++);
		if (c == 10)
			write_char(13);
		write_char(c);
	}

	__flush_console();

	if (need_unlock)
		unlock(&con_lock);

	return count;
}

ssize_t read(int fd __unused, void *buf, size_t req_count)
{
	bool need_unlock = lock_recursive(&con_lock);
	size_t count = 0;

	if (con_driver && con_driver->read)
		count = con_driver->read(buf, req_count);
	if (!count)
		count = inmem_read(buf, req_count);
	if (need_unlock)
		unlock(&con_lock);
	return count;
}

void set_console(struct con_ops *driver)
{
	con_driver = driver;
	if (driver)
		flush_console();
}

void memcons_add_properties(void)
{
	uint64_t addr = (u64)&memcons;

	dt_add_property_cells(opal_node, "ibm,opal-memcons",
			      hi32(addr), lo32(addr));
}

/*
 * Default OPAL console provided if nothing else overrides it
 */
static int64_t dummy_console_write(int64_t term_number, int64_t *length,
				   const uint8_t *buffer)
{
	if (term_number != 0)
		return OPAL_PARAMETER;
	write(0, buffer, *length);

	return OPAL_SUCCESS;
}
opal_call(OPAL_CONSOLE_WRITE, dummy_console_write, 3);

static int64_t dummy_console_write_buffer_space(int64_t term_number,
						int64_t *length)
{
	if (term_number != 0)
		return OPAL_PARAMETER;
	if (length)
		*length = INMEM_CON_OUT_LEN;

	return OPAL_SUCCESS;
}
opal_call(OPAL_CONSOLE_WRITE_BUFFER_SPACE, dummy_console_write_buffer_space, 2);

static int64_t dummy_console_read(int64_t term_number, int64_t *length,
				  uint8_t *buffer)
{
	if (term_number != 0)
		return OPAL_PARAMETER;
	*length = read(0, buffer, *length);

	return OPAL_SUCCESS;
}
opal_call(OPAL_CONSOLE_READ, dummy_console_read, 3);

static void dummy_console_poll(void *data __unused)
{
	bool uart_has_data;

	lock(&con_lock);
	uart_has_data = uart_console_poll();

	if (uart_has_data || memcons.in_prod != memcons.in_cons)
		opal_update_pending_evt(OPAL_EVENT_CONSOLE_INPUT,
					OPAL_EVENT_CONSOLE_INPUT);
	else
		opal_update_pending_evt(OPAL_EVENT_CONSOLE_INPUT, 0);
	unlock(&con_lock);

}

void dummy_console_add_nodes(void)
{
	struct dt_node *con, *consoles;

	consoles = dt_new(opal_node, "consoles");
	assert(consoles);
	dt_add_property_cells(consoles, "#address-cells", 1);
	dt_add_property_cells(consoles, "#size-cells", 0);

	con = dt_new_addr(consoles, "serial", 0);
	assert(con);
	dt_add_property_string(con, "compatible", "ibm,opal-console-raw");
	dt_add_property_cells(con, "#write-buffer-size", INMEM_CON_OUT_LEN);
	dt_add_property_cells(con, "reg", 0);
	dt_add_property_string(con, "device_type", "serial");

	dt_add_property_string(dt_chosen, "linux,stdout-path",
			       "/ibm,opal/consoles/serial@0");

	opal_add_poller(dummy_console_poll, NULL);
}
