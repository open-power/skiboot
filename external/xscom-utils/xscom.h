#ifndef __XSCOM_H
#define __XSCOM_H

#include <stdint.h>

extern int xscom_read(uint32_t chip_id, uint64_t addr, uint64_t *val);
extern int xscom_write(uint32_t chip_id, uint64_t addr, uint64_t val);

extern int xscom_read_ex(uint32_t ex_target_id, uint64_t addr, uint64_t *val);
extern int xscom_write_ex(uint32_t ex_target_id, uint64_t addr, uint64_t val);

extern void xscom_for_each_chip(void (*cb)(uint32_t chip_id));

extern uint32_t xscom_init(void);

#endif /* __XSCOM_H */
