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


#ifndef __ASTBMC_H
#define __ASTBMC_H

extern void astbmc_early_init(void);
extern int64_t astbmc_ipmi_reboot(void);
extern int64_t astbmc_ipmi_power_down(uint64_t request);
extern void astbmc_init(void);
extern void astbmc_ext_irq_serirq_cpld(unsigned int chip_id);
extern int pnor_init(void);

#endif /* __ASTBMC_H */
