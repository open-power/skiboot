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

#include <unistd.h>
#include "blocklevel.h"

int blocklevel_read(struct blocklevel_device *bl, uint32_t pos, void *buf, uint32_t len)
{
	if (!bl || !bl->read || !buf)
		return -1;

	return bl->read(bl, pos, buf, len);
}

int blocklevel_write(struct blocklevel_device *bl, uint32_t pos, const void *buf, uint32_t len)
{
	if (!bl || !bl->write || !buf)
		return -1;

	return bl->write(bl, pos, buf, len);
}

int blocklevel_erase(struct blocklevel_device *bl, uint32_t pos, uint32_t len)
{
	if (!bl || !bl->erase)
		return -1;

	return bl->erase(bl, pos, len);
}

int blocklevel_get_info(struct blocklevel_device *bl, const char **name, uint32_t *total_size,
		uint32_t *erase_granule)
{
	if (!bl || !bl->get_info)
		return -1;

	return bl->get_info(bl, name, total_size, erase_granule);
}
