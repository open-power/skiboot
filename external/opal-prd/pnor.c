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
#include <err.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <mtd/mtd-user.h>

#include <pnor.h>

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
		fprintf(stderr, "PNOR: ioctl failed to get pnor info\n");
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

	printf("Found PNOR: %d bytes (%d blocks)\n", pnor->size,
	       pnor->erasesize);

	rc = ffs_open_image(fd, pnor->size, 0, &pnor->ffsh);
	if (rc)
		fprintf(stderr, "Failed to open pnor partition table\n");

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

	printf(" %10s %8s %8s %8s\n", "name", "start", "size", "act_size");
	for (i = 0; ; i++) {
		rc = ffs_part_info(ffs, i, &name, &start,
				&size, &act_size, NULL);
		if (rc)
			break;
		printf(" %10s %08x %08x %08x\n", name, start, size, act_size);
		free(name);
	}
}

int mtd_write(struct pnor *pnor, int fd, void *data, uint64_t offset,
	      size_t len)
{
	int write_start, write_len, start_waste, rc;
	bool end_waste = false;
	uint8_t *buf;
	struct erase_info_user erase;

	if (len > pnor->size || offset > pnor->size ||
	    len + offset > pnor->size)
		return -1;

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
			perror("lseek write_start");
			goto out;
		}

		read(fd, buf, pnor->erasesize);
	}

	if (end_waste)  {
		rc = lseek(fd, write_start + write_len - pnor->erasesize,
			   SEEK_SET);
		if (rc < 0) {
			perror("lseek last write block");
			goto out;
		}

		read(fd, buf + write_len - pnor->erasesize, pnor->erasesize);
	}

	/* Put data in the correct spot */
	memcpy(buf + start_waste, data, len);

	/* Not sure if this is required */
	rc = lseek(fd, 0, SEEK_SET);
	if (rc < 0) {
		perror("lseek 0");
		goto out;
	}

	/* Erase */
	erase.start = write_start;
	erase.length = write_len;

	rc = ioctl(fd, MEMERASE, &erase);
	if (rc < 0) {
		perror("ioctl MEMERASE");
		goto out;
	}

	/* Write */
	rc = lseek(fd, write_start, SEEK_SET);
	if (rc < 0) {
		perror("lseek write_start");
		goto out;
	}

	rc = write(fd, buf, write_len);
	if (rc < 0) {
		perror("write to fd");
		goto out;
	}

	/* We have succeded, report the requested write size */
	rc = len;

out:
	free(buf);
	return rc;
}

int mtd_read(struct pnor *pnor, int fd, void *data, uint64_t offset,
	     size_t len)
{
	int read_start, read_len, start_waste, rc;
	int mask = pnor->erasesize - 1;
	void *buf;

	if (len > pnor->size || offset > pnor->size ||
	    len + offset > pnor->size)
		return -1;

	/* Align start to erase block size */
	start_waste = offset % pnor->erasesize;
	read_start = offset - start_waste;

	/* Align size to multiple of block size */
	read_len = (len + start_waste) & ~mask;
	if ((len + start_waste) > read_len)
		read_len += pnor->erasesize;

	/* Ensure read is not out of bounds */
	if (read_start + read_len > pnor->size) {
		fprintf(stderr, "PNOR: read out of bounds\n");
		return -1;
	}

	buf = malloc(read_len);

	rc = lseek(fd, read_start, SEEK_SET);
	if (rc < 0) {
		perror("lseek read_start");
		goto out;
	}

	rc = read(fd, buf, read_len);
	if (rc < 0) {
		perror("read from fd");
		goto out;
	}

	/* Copy data into destination, cafefully avoiding the extra data we
	 * added to align to block size */
	memcpy(data, buf + start_waste, len);
	rc = len;
out:
	free(buf);
	return rc;
}

int pnor_operation(struct pnor *pnor, const char *name, uint64_t offset,
		   void *data, size_t size, enum pnor_op op)
{
	int rc, fd;
	uint32_t pstart, psize, idx;

	if (!pnor->ffsh)
		return -1;

	rc = ffs_lookup_part(pnor->ffsh, name, &idx);
	if (rc)
		return -1;

	ffs_part_info(pnor->ffsh, idx, NULL, &pstart, &psize, NULL, NULL);
	if (rc)
		return -1;

	if (size > psize || offset > psize || size + offset > psize)
		return -1;

	fd = open(pnor->path, O_RDWR);
	if (fd < 0) {
		perror(pnor->path);
		return fd;
	}

	rc = lseek(fd, pstart, SEEK_SET);
	if (rc < 0) {
		perror(pnor->path);
		goto out;
	}

	switch (op) {
	case PNOR_OP_READ:
		rc = mtd_read(pnor, fd, data, offset, size);
		break;
	case PNOR_OP_WRITE:
		rc = mtd_write(pnor, fd, data, offset, size);
		break;
	default:
		rc  = -1;
		fprintf(stderr, "PNOR: Invalid operation\n");
		goto out;
	}

	if (rc < 0)
		warn("PNOR: MTD operation failed");
	else if (rc != size)
		warnx("PNOR: mtd operation returned %d, expected %zd",
				rc, size);
	else
		rc = 0;


out:
	close(fd);

	return rc;
}
