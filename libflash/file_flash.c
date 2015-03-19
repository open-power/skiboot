#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>

#include <mtd/mtd-abi.h>

#include "file_flash.h"

/* The caller is going to have to supply this */
struct file_flash_priv {
	int fd;
};

/*
 * Unfortunately not all file descriptors are created equal...
 * Here we check to see if the file descriptor is to an MTD device, in which
 * case we have to get the size of it differently.
 */
int file_setup(struct spi_flash_ctrl *ctrl, uint32_t *tsize)
{
	struct mtd_info_user mtd_info;
	struct file_flash_priv *file_flash_data;
	struct stat sbuf;

	if (!ctrl || !ctrl->priv)
		return -1;

	file_flash_data = (struct file_flash_priv *)ctrl->priv;

	if (fstat(file_flash_data->fd, &sbuf) == -1)
		return -1;

	if (S_ISCHR(sbuf.st_mode)) {
		if (ioctl(file_flash_data->fd, MEMGETINFO, &mtd_info) == -1)
			return -1;

		ctrl->finfo->size = mtd_info.size;

	} else if (S_ISREG(sbuf.st_mode)) {
		ctrl->finfo->size = sbuf.st_size;

	} else {
		/* Not going to be able to work with anything else */
		return -1;
	}

	if (tsize)
		*tsize = ctrl->finfo->size;

	return 0;
}

int file_set4b(struct spi_flash_ctrl *ctrl, bool enable)
{
	/* Always report success no matter what, this isn't relevent for files */
	return 0;
}

int file_chipid(struct spi_flash_ctrl *ctrl, uint8_t *id_buf,
		uint32_t *id_size)
{
	if (!ctrl || !ctrl->priv || !id_size || *id_size < 3)
		return -1;

	id_buf[0] = 'M';
	id_buf[1] = 'T';
	id_buf[2] = 'D';

	*id_size = 3;
	return 0;
}

int file_read(struct spi_flash_ctrl *ctrl, uint32_t addr, void *buf,
		uint32_t size)
{
	int rc;
	struct file_flash_priv *file_flash_data;

	if (!ctrl || !ctrl->priv)
		return -1;

	file_flash_data = (struct file_flash_priv *)ctrl->priv;

	rc = lseek(file_flash_data->fd, addr, SEEK_SET);
	if ((off_t )rc == (off_t )-1)
		return -1;

	rc = read(file_flash_data->fd, buf, size);
	if (rc == -1)
		return -1;
	/* TODO Perhaps deal with short reads */

	return 0;
}

int file_write(struct spi_flash_ctrl *ctrl, uint32_t addr,
		const void *buf, uint32_t size)
{
	size_t rc;
	struct file_flash_priv *file_flash_data;

	if (!ctrl || !ctrl->priv)
		return -1;

	file_flash_data = (struct file_flash_priv *)ctrl->priv;

	rc = lseek(file_flash_data->fd, addr, SEEK_SET);
	if ((off_t )rc == (off_t )-1)
		return -1;

	rc = write(file_flash_data->fd, buf, size);
	if (rc != size)
		return -1;
	/* TODO Perhaps deal with short writes */

	return 0;
}

int file_erase(struct spi_flash_ctrl *ctrl, uint32_t addr,
		uint32_t size)
{
	struct stat sbuf;
	struct file_flash_priv *file_flash_data;
	uint32_t esize;

	if (!ctrl || !ctrl->priv)
		return -1;

	/*
	 * Input params addr = 0 and size = 0xffffffff mean libflash is telling us
	 * to erase the entire thing.
	 */
	file_flash_data = (struct file_flash_priv *)ctrl->priv;

	esize = (size == 0xffffffff && addr == 0) ? ctrl->finfo->size : size;
	if (esize > ctrl->finfo->size)
		return -1;

	if (fstat(file_flash_data->fd, &sbuf) == -1)
		return -1;

	/*
	 * If we're dealing with an MTD device then its possible that there is a
	 * real flash device somewhere (as opposed to a regular file where the
	 * assumption is that there is not).
	 * In that case lets try to represerve that idea and use the erase ioctl.
	 */
	if (S_ISCHR(sbuf.st_mode)) {
		struct erase_info_user erase_info = {
			.start = addr,
			.length = esize
		};

		if (ioctl(file_flash_data->fd, MEMERASE, erase_info) == -1)
			return -1;

	} else if (S_ISREG(sbuf.st_mode)) {
		/* Regular file, erase is just write zeros */
		char *section;

		section = mmap(NULL, sbuf.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, file_flash_data->fd, 0);
		if (section == (void *)-1)
			return -1;
		bzero(section + addr, esize);
		if (munmap(section, sbuf.st_size) == -1)
			return -1;

	} else {
		return -1;
	}

	return 0;
}

/* To be called by tools wanting to use the libflash/libffs APIs */
struct spi_flash_ctrl *build_flash_ctrl(int fd)
{
	struct spi_flash_ctrl *ctrl;
	struct file_flash_priv *data;

	ctrl = calloc(1, sizeof(struct spi_flash_ctrl));
	if (!ctrl)
		return NULL;

	data = calloc(1, sizeof(struct file_flash_priv));
	if (!data) {
		free(ctrl);
		return NULL;
	}

	data->fd = fd;

	/*
	 * Don't implement the low level interfaces because we aren't flash. This
	 * will also force libflash to only call us with the high level interface.
	 */
	ctrl->cmd_rd = NULL;
	ctrl->cmd_wr = NULL;

	/*
	 * Do implement everything else.
	 */
	ctrl->erase = &file_erase;
	ctrl->write = &file_write;
	ctrl->read = &file_read;
	ctrl->chip_id = &file_chipid;
	ctrl->set_4b = &file_set4b;
	ctrl->setup = &file_setup;

	ctrl->priv = data;

	return ctrl;
}

void free_flash_ctrl(struct spi_flash_ctrl *flash_ctrl)
{
	free(flash_ctrl->priv);
	free(flash_ctrl);
}
