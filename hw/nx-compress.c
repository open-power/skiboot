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

#include <skiboot.h>
#include <chip.h>
#include <xscom.h>
#include <io.h>
#include <cpu.h>
#include <nx.h>

void nx_create_compress_node(struct dt_node *node)
{
	u32 gcid, pb_base;

	gcid = dt_get_chip_id(node);
	pb_base = dt_get_address(node, 0, NULL);

	prlog(PR_INFO, "NX%d: 842 at 0x%x\n", gcid, pb_base);

	nx_enable_842(node, gcid, pb_base);
}
