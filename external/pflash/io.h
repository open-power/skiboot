#ifndef __IO_H
#define __IO_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include <libflash/libflash.h>

/* AST AHB register base */
#define AHB_REGS_BASE		0x1E600000
#define AHB_REGS_SIZE		0x00200000

/* AST GPIO control regs */
#define GPIO_CTRL_BASE		0x1E780000
#define GPIO_CTRL_SIZE		0x1000

/* AST AHB mapping of PNOR */
#define PNOR_FLASH_BASE		0x30000000
#define PNOR_FLASH_SIZE		0x04000000

/* AST AHB mapping of BMC flash */
#define BMC_FLASH_BASE		0x20000000
#define BMC_FLASH_SIZE		0x04000000

/* Address of flash mapping on LPC FW space */
#define LPC_FLASH_BASE		0x0e000000
#define LPC_CTRL_BASE		0x1e789000

extern void open_devs(bool use_lpc, bool bmc_flash);
extern bool set_wrprotect(bool protect);

#ifdef __powerpc__

extern void close_devs(void);

/* AST access functions */
extern uint32_t (*ast_ahb_readl)(uint32_t offset);
extern void (*ast_ahb_writel)(uint32_t val, uint32_t offset);
extern int (*ast_copy_to_ahb)(uint32_t reg, const void *src, uint32_t len);
extern int (*ast_copy_from_ahb)(void *dst, uint32_t reg, uint32_t len);

/* SFC LPC access functions (big endian) */
extern int lpc_fw_write32(uint32_t val, uint32_t addr);
extern int lpc_fw_read32(uint32_t *val, uint32_t addr);

extern void check_platform(bool *has_sfc, bool *has_ast);

#else

static inline void close_devs(void) { }

static inline uint8_t readb(void *addr)
{
	asm volatile("" : : : "memory");
	return *(volatile uint8_t *)addr;
}

static inline uint16_t readw(void *addr)
{
	asm volatile("" : : : "memory");
	return *(volatile uint16_t *)addr;
}

static inline uint32_t readl(void *addr)
{
	asm volatile("" : : : "memory");
	return *(volatile uint32_t *)addr;
}

static inline void writeb(uint8_t val, void *addr)
{
	asm volatile("" : : : "memory");
	*(volatile uint8_t *)addr = val;
}

static inline void writew(uint16_t val, void *addr)
{
	asm volatile("" : : : "memory");
	*(volatile uint16_t *)addr = val;
}

static inline void writel(uint32_t val, void *addr)
{
	asm volatile("" : : : "memory");
	*(volatile uint32_t *)addr = val;
}

/*
 * AHB register and flash access
 */

extern void *ahb_reg_map;

static inline uint32_t ast_ahb_readl(uint32_t offset)
{
	assert(((offset ^ AHB_REGS_BASE) & ~(AHB_REGS_SIZE - 1)) == 0);

	return readl(ahb_reg_map + (offset - AHB_REGS_BASE));
}

static inline void ast_ahb_writel(uint32_t val, uint32_t offset)
{
	assert(((offset ^ AHB_REGS_BASE) & ~(AHB_REGS_SIZE - 1)) == 0);

	writel(val, ahb_reg_map + (offset - AHB_REGS_BASE));
}

extern int ast_copy_to_ahb(uint32_t reg, const void *src, uint32_t len);
extern int ast_copy_from_ahb(void *dst, uint32_t reg, uint32_t len);

static inline void check_platform(bool *has_sfc, bool *has_ast)
{
	*has_sfc = false;
	*has_ast = true;
}

#endif

#endif /* __IO_H */

