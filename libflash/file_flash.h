#ifndef __FILE_FLASH_H
#define __FILE_FLASH_H

#include <libflash/libflash.h>
#include <libflash/libflash-priv.h>

struct spi_flash_ctrl *build_flash_ctrl(int fd);

void free_flash_ctrl(struct spi_flash_ctrl *flash_ctrl);

#endif /* __FILE_FLASH_H */
