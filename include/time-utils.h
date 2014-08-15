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

#ifndef __TIME_UTILS_H
#define __TIME_UTILS_H

#include <stdint.h>
#include <time.h>

void tm_to_datetime(struct tm *tm, uint32_t *y_m_d, uint64_t *h_m_s_m);
void datetime_to_tm(uint32_t y_m_d, uint64_t h_m_s_m, struct tm *tm);

#endif
