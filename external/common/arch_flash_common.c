/* Copyright 2015 IBM Corp.
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

#include <libflash/blocklevel.h>

#include "arch_flash.h"

/* Default implmentations */
int __attribute__((weak)) arch_flash_erase_chip(struct blocklevel_device *bl)
{
	return -1;
}

int __attribute__((weak)) arch_flash_4b_mode(struct blocklevel_device *bl, int set_4b)
{
	return -1;
}

enum flash_access __attribute__((weak)) arch_flash_access(struct blocklevel_device *bl, enum flash_access access)
{
	return ACCESS_INVAL;
}

int __attribute__((weak)) arch_flash_set_wrprotect(struct blocklevel_device *bl, int set)
{
	return -1;
}
