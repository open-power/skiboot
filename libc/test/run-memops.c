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

#define BUFSZ 50

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

int test_memset(char* buf, int c, size_t s);

int main(void)
{
	char* buf;

	buf = malloc(100);
	assert(test_memset(buf, 0x42, 100) == 0);
	free(buf);

	buf = malloc(128);
	assert(test_memset(buf, 0, 128) == 0);
	assert(test_memset(buf+1, 0, 127) == 0);
	free(buf);

	buf = malloc(1024);
	assert(test_memset(buf, 0, 1024) == 0);
	free(buf);

	return 0;
}
