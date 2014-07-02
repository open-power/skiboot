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


#ifndef __IBM_FSP_COMMON_H
#define __IBM_FSP_COMMON_H

extern void ibm_fsp_init(void);

extern int64_t ibm_fsp_cec_power_down(uint64_t request);
extern int64_t ibm_fsp_cec_reboot(void);

#endif /*  __IBM_FSP_COMMON_H */
