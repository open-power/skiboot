/* Copyright 2013-2014 IBM Corp.
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

#ifndef __BT_H
#define __BT_H

#include <ipmi.h>

/* Initialise the BT interface */
void bt_init(void (*ipmi_cmd_done)(struct ipmi_msg *));

/* Allocate an BT-IPMI message */
struct ipmi_msg *bt_alloc_ipmi_msg(size_t request_size, size_t response_size);

/* Free a BT-IPMI message */
void bt_free_ipmi_msg(struct ipmi_msg *ipmi_msg);

/* Add an IPMI message to the BT queue and wait for a resposne */
int bt_add_ipmi_msg_wait(struct ipmi_msg *msg);

/* Remove an IPMI message from the BT queue */
void bt_del_ipmi_msg(struct ipmi_msg *ipmi_msg);

#endif
