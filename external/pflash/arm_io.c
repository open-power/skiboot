#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <byteswap.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <limits.h>
#include <arpa/inet.h>
#include <assert.h>

#include "io.h"

void *ahb_reg_map;
void *ahb_flash_map;
uint32_t ahb_flash_base, ahb_flash_size;
void *gpio_ctrl;

int ast_copy_to_ahb(uint32_t reg, const void *src, uint32_t len)
{
	if (reg < ahb_flash_base ||
	    (reg + len) > (ahb_flash_base + ahb_flash_size))
		return -1;
	reg -= ahb_flash_base;

	if (((reg | (unsigned long)src | len) & 3) == 0) {
		while(len > 3) {
			uint32_t val = *(uint32_t *)src;
			writel(val, ahb_flash_map + reg);
			src += 4;
			reg += 4;
			len -= 4;
		}
	}

	while(len--) {
		uint8_t val = *(uint8_t *)src;
		writeb(val, ahb_flash_map + reg++);
		src += 1;
	}
	return 0;
}


int ast_copy_from_ahb(void *dst, uint32_t reg, uint32_t len)
{
	if (reg < ahb_flash_base ||
	    (reg + len) > (ahb_flash_base + ahb_flash_size))
		return -1;
	reg -= ahb_flash_base;

	if (((reg | (unsigned long)dst | len) & 3) == 0) {
		while(len > 3) {
			*(uint32_t *)dst = readl(ahb_flash_map + reg);
			dst += 4;
			reg += 4;
			len -= 4;
		}
	}

	while(len--) {
		*(uint8_t *)dst = readb(ahb_flash_map + reg++);
		dst += 1;
	}
	return 0;
}

/*
 * GPIO stuff to be replaced by higher level accessors for
 * controlling the flash write lock via sysfs
 */

static inline uint32_t gpio_ctl_readl(uint32_t offset)
{
	return readl(gpio_ctrl + offset);
}

static inline void gpio_ctl_writel(uint32_t val, uint32_t offset)
{
	writel(val, gpio_ctrl + offset);
}


bool set_wrprotect(bool protect)
{
	uint32_t reg;
	bool was_protected;

	reg = gpio_ctl_readl(0x20);
	was_protected = !!(reg & 0x00004000);
	if (protect)
		reg |= 0x00004000; /* GPIOF[6] value */
	else
		reg &= ~0x00004000; /* GPIOF[6] value */
	gpio_ctl_writel(reg, 0x20);
	reg = gpio_ctl_readl(0x24);
	reg |= 0x00004000; /* GPIOF[6] direction */
	gpio_ctl_writel(reg, 0x24);

	return was_protected;
}

void open_devs(bool use_lpc, bool bmc_flash)
{
	int fd;

	(void)use_lpc;

	fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd < 0) {
		perror("can't open /dev/mem");
		exit(1);
	}
	ahb_reg_map = mmap(0, AHB_REGS_SIZE, PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, AHB_REGS_BASE);
	if (ahb_reg_map == MAP_FAILED) {
		perror("can't map AHB registers /dev/mem");
		exit(1);
	}
	gpio_ctrl = mmap(0, GPIO_CTRL_SIZE, PROT_READ | PROT_WRITE,
			 MAP_SHARED, fd, GPIO_CTRL_BASE);
	if (gpio_ctrl == MAP_FAILED) {
		perror("can't map GPIO control via /dev/mem");
		exit(1);
	}
	ahb_flash_base = bmc_flash ? BMC_FLASH_BASE : PNOR_FLASH_BASE;
	ahb_flash_size = bmc_flash ? BMC_FLASH_SIZE : PNOR_FLASH_SIZE;
	ahb_flash_map = mmap(0, ahb_flash_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, fd, ahb_flash_base);
	if (ahb_flash_map == MAP_FAILED) {
		perror("can't map flash via /dev/mem");
		exit(1);
	}
}
