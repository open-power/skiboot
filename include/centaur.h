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

#ifndef __CENTAUR_H
#define __CENTAUR_H

extern int64_t centaur_xscom_read(uint32_t id, uint64_t pcb_addr, uint64_t *val) __warn_unused_result;
extern int64_t centaur_xscom_write(uint32_t id, uint64_t pcb_addr, uint64_t val) __warn_unused_result;
extern void centaur_init(void);

#endif /* __CENTAUR_H */
