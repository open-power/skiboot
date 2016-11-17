/* Copyright 2013-2016 IBM Corp.
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

#include <config.h>

#include <stdbool.h>
#include <types.h>
#include "container.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>

int main(int argc, char* argv[])
{
	int fdin, fdout;
	void *container = malloc(SECURE_BOOT_HEADERS_SIZE);
	struct stat s;
	char *buf = malloc(4096);
	off_t l;
	void *infile;
	int r;
	ROM_container_raw *c = (ROM_container_raw*)container;
	ROM_prefix_header_raw *ph;
	ROM_prefix_data_raw *pd;
	ROM_sw_header_raw *swh;

	memset(container, 0, SECURE_BOOT_HEADERS_SIZE);

	if (argc<3)
		return -1;

	fdin = open(argv[1], O_RDONLY);
	assert(fdin > 0);
	r = fstat(fdin, &s);
	assert(r==0);
	infile = mmap(NULL, s.st_size, PROT_READ, 0, fdin, 0);
	assert(infile);
	fdout = open(argv[2], O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	assert(fdout > 0);

	c->magic_number = cpu_to_be32(ROM_MAGIC_NUMBER);
	c->version = 1;
	c->container_size = cpu_to_be64(SECURE_BOOT_HEADERS_SIZE + s.st_size);
	c->target_hrmor = 0;
	c->stack_pointer = 0;
	memset(c->hw_pkey_a, 0, sizeof(ecc_key_t));
	memset(c->hw_pkey_b, 0, sizeof(ecc_key_t));
	memset(c->hw_pkey_c, 0, sizeof(ecc_key_t));

	ph = container + sizeof(ROM_container_raw);
	ph->ver_alg.version = cpu_to_be16(1);
	ph->ver_alg.hash_alg = 1;
	ph->ver_alg.sig_alg = 1;
	ph->code_start_offset = 0;
	ph->reserved = 0;
	ph->flags = 0;
	ph->sw_key_count = 1; // 1, not 0. Because Hostboot
	memset(ph->payload_hash, 0, sizeof(sha2_hash_t)); // TODO
	ph->ecid_count = 0;

	pd = (ROM_prefix_data_raw*)ph->ecid;
	memset(pd->hw_sig_a, 0, sizeof(ecc_signature_t));
	memset(pd->hw_sig_b, 0, sizeof(ecc_signature_t));
	memset(pd->hw_sig_c, 0, sizeof(ecc_signature_t));
	memset(pd->sw_pkey_p, 0, sizeof(ecc_key_t));
	memset(pd->sw_pkey_q, 0, sizeof(ecc_key_t));
	memset(pd->sw_pkey_r, 0, sizeof(ecc_key_t));
	ph->payload_size = cpu_to_be64(sizeof(ecc_signature_t)*3 + ph->sw_key_count * sizeof(ecc_key_t));

	swh = (ROM_sw_header_raw*)(((void*)pd) + be64_to_cpu(ph->payload_size));
	swh->ver_alg.version = cpu_to_be16(1);
	swh->ver_alg.hash_alg = 1;
	swh->ver_alg.sig_alg = 1;
	swh->code_start_offset = 0;
	swh->reserved = 0;
	swh->flags = 0;
	swh->reserved_0 = 0;
	swh->payload_size = cpu_to_be64(s.st_size);

	r = write(fdout, container, SECURE_BOOT_HEADERS_SIZE);
	assert(r == 4096);
	read(fdin, buf, s.st_size%4096);
	write(fdout, buf, s.st_size%4096);
	l = s.st_size - s.st_size%4096;
	while (l) {
		read(fdin, buf, 4096);
		write(fdout, buf, 4096);
		l-=4096;
	};
	close(fdin);
	close(fdout);

	free(container);
	free(buf);
	return 0;
}
