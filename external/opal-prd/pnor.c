/* Copyright 2013-2015 IBM Corp.
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

#include <libflash/libffs.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <mtd/mtd-user.h>

#include "pnor.h"
#include "opal-prd.h"

int pnor_init(struct pnor *pnor)
{
	int rc, fd;
	mtd_info_t mtd_info;

	if (!pnor)
		return -1;

	/* Open device and ffs */
	fd = open(pnor->path, O_RDWR);
	if (fd < 0) {
		perror(pnor->path);
		return -1;
	}

	/* Hack so we can test on non-mtd file descriptors */
#if defined(__powerpc__)
	rc = ioctl(fd, MEMGETINFO, &mtd_info);
	if (rc < 0) {
		pr_log(LOG_ERR, "PNOR: ioctl failed to get pnor info: %m");
		goto out;
	}
	pnor->size = mtd_info.size;
	pnor->erasesize = mtd_info.erasesize;
#else
	pnor->size = lseek(fd, 0, SEEK_END);
	if (pnor->size < 0) {
		perror(pnor->path);
		goto out;
	}
	/* Fake it */
	pnor->erasesize = 1024;
#endif

	pr_debug("PNOR: Found PNOR: %d bytes (%d blocks)", pnor->size,
	       pnor->erasesize);

	rc = ffs_open_image(fd, pnor->size, 0, &pnor->ffsh);
	if (rc)
		pr_log(LOG_ERR, "PNOR: Failed to open pnor partition table");

out:
	close(fd);

	return rc;
}

void pnor_close(struct pnor *pnor)
{
	if (!pnor)
		return;

	if (pnor->ffsh)
		ffs_close(pnor->ffsh);

	if (pnor->path)
		free(pnor->path);
}

void dump_parts(struct ffs_handle *ffs) {
	int i, rc;
	uint32_t start, size, act_size;
	char *name;

	pr_debug("PNOR: %10s %8s %8s %8s",
			"name", "start", "size", "act_size");
	for (i = 0; ; i++) {
		rc = ffs_part_info(ffs, i, &name, &start,
				&size, &act_size, NULL);
		if (rc)
			break;
		pr_debug("PNOR: %10s %08x %08x %08x",
				name, start, size, act_size);
		free(name);
	}
}

static int mtd_write(struct pnor *pnor, int fd, void *data, uint64_t offset,
		     size_t len)
{
	int write_start, write_len, start_waste, rc;
	bool end_waste = false;
	uint8_t *buf;
	struct erase_info_user erase;

	if (len > pnor->size || offset > pnor->size ||
	    len + offset > pnor->size)
		return -ERANGE;

	start_waste = offset % pnor->erasesize;
	write_start = offset - start_waste;

	/* Align size to multiple of block size */
	write_len = (len + start_waste) & ~(pnor->erasesize - 1);
	if ((len + start_waste) > write_len) {
		end_waste = true;
		write_len += pnor->erasesize;
	}

	buf = malloc(write_len);

	if (start_waste) {
		rc = lseek(fd, write_start, SEEK_SET);
		if (rc < 0) {
			pr_log(LOG_ERR, "PNOR: lseek write_start(0x%x) "
					"failed; %m", write_start);
			goto out;
		}

		read(fd, buf, pnor->erasesize);
	}

	if (end_waste)  {
		rc = lseek(fd, write_start + write_len - pnor->erasesize,
			   SEEK_SET);
		if (rc < 0) {
			perror("lseek last write block");
			pr_log(LOG_ERR, "PNOR: lseek last write block(0x%x) "
					"failed; %m",
						write_start + write_len -
						pnor->erasesize);
			goto out;
		}

		read(fd, buf + write_len - pnor->erasesize, pnor->erasesize);
	}

	/* Put data in the correct spot */
	memcpy(buf + start_waste, data, len);

	/* Not sure if this is required */
	rc = lseek(fd, 0, SEEK_SET);
	if (rc < 0) {
		pr_log(LOG_NOTICE, "PNOR: lseek(0) failed: %m");
		goto out;
	}

	/* Erase */
	erase.start = write_start;
	erase.length = write_len;

	rc = ioctl(fd, MEMERASE, &erase);
	if (rc < 0) {
		pr_log(LOG_ERR, "PNOR: erase(start 0x%x, len 0x%x) ioctl "
				"failed: %m", write_start, write_len);
		goto out;
	}

	/* Write */
	rc = lseek(fd, write_start, SEEK_SET);
	if (rc < 0) {
		pr_log(LOG_ERR, "PNOR: lseek write_start(0x%x) failed: %m",
				write_start);
		goto out;
	}

	rc = write(fd, buf, write_len);
	if (rc < 0) {
		pr_log(LOG_ERR, "PNOR: write(0x%x bytes) failed: %m",
				write_len);
		goto out;
	}

	/* We have succeded, report the requested write size */
	rc = len;

out:
	free(buf);
	return rc;
}

static int mtd_read(struct pnor *pnor, int fd, void *data, uint64_t offset,
		    size_t len)
{
	int read_start, read_len, start_waste, rc;
	int mask = pnor->erasesize - 1;
	void *buf;

	if (len > pnor->size || offset > pnor->size ||
	    len + offset > pnor->size)
		return -ERANGE;

	/* Align start to erase block size */
	start_waste = offset % pnor->erasesize;
	read_start = offset - start_waste;

	/* Align size to multiple of block size */
	read_len = (len + start_waste) & ~mask;
	if ((len + start_waste) > read_len)
		read_len += pnor->erasesize;

	/* Ensure read is not out of bounds */
	if (read_start + read_len > pnor->size) {
		pr_log(LOG_ERR, "PNOR: read out of bounds");
		return -ERANGE;
	}

	buf = malloc(read_len);

	rc = lseek(fd, read_start, SEEK_SET);
	if (rc < 0) {
		pr_log(LOG_ERR, "PNOR: lseek read_start(0x%x) failed: %m",
				read_start);
		goto out;
	}

	rc = read(fd, buf, read_len);
	if (rc < 0) {
		pr_log(LOG_ERR, "PNOR: write(offset 0x%x, len 0x%x) "
				"failed: %m", read_start, read_len);
		goto out;
	}

	/* Copy data into destination, carefully avoiding the extra data we
	 * added to align to block size */
	memcpy(data, buf + start_waste, len);
	rc = len;
out:
	free(buf);
	return rc;
}

/* Similar to read(2), this performs partial operations where the number of
 * bytes read/written may be less than size.
 *
 * Returns number of bytes written, or a negative value on failure. */
int pnor_operation(struct pnor *pnor, const char *name, uint64_t offset,
		   void *data, size_t requested_size, enum pnor_op op)
{
	int rc, fd;
	uint32_t pstart, psize, idx;
	int size;

	if (!pnor->ffsh) {
		pr_log(LOG_ERR, "PNOR: ffs not initialised");
		return -EBUSY;
	}

	rc = ffs_lookup_part(pnor->ffsh, name, &idx);
	if (rc) {
		pr_log(LOG_WARNING, "PNOR: no partiton named '%s'", name);
		return -ENOENT;
	}

	ffs_part_info(pnor->ffsh, idx, NULL, &pstart, &psize, NULL, NULL);
	if (rc) {
		pr_log(LOG_ERR, "PNOR: unable to fetch partition info for %s",
				name);
		return -ENOENT;
	}

	if (offset > psize) {
		pr_log(LOG_WARNING, "PNOR: partition %s(size 0x%x) "
				"offset (0x%lx) out of bounds",
				name, psize, offset);
		return -ERANGE;
	}

	/* Large requests are trimmed */
	if (requested_size > psize)
		size = psize;
	else
		size = requested_size;

	if (size + offset > psize)
		size = psize - offset;

	if (size < 0) {
		pr_log(LOG_WARNING, "PNOR: partition %s(size 0x%x) "
				"read size (0x%zx) and offset (0x%lx) "
				"out of bounds",
				name, psize, requested_size, offset);
		return -ERANGE;
	}

	fd = open(pnor->path, O_RDWR);
	if (fd < 0) {
		perror(pnor->path);
		return fd;
	}

	switch (op) {
	case PNOR_OP_READ:
		rc = mtd_read(pnor, fd, data, pstart + offset, size);
		break;
	case PNOR_OP_WRITE:
		rc = mtd_write(pnor, fd, data, pstart + offset, size);
		break;
	default:
		rc  = -EIO;
		pr_log(LOG_ERR, "PNOR: Invalid operation");
		goto out;
	}

	if (rc < 0)
		pr_log(LOG_ERR, "PNOR: MTD operation failed");
	else if (rc != size)
		pr_log(LOG_WARNING, "PNOR: mtd operation "
				"returned %d, expected %d",
				rc, size);

out:
	close(fd);

	return rc;
}
