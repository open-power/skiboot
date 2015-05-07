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

#include <compiler.h>

typedef long gcov_type;

void __gcov_init(void* f) __attrconst;
void __gcov_flush(void) __attrconst;
void __gcov_merge_add(gcov_type *counters, unsigned int n_counters) __attrconst;
void __gcov_merge_single(gcov_type *counters, unsigned int n_counters) __attrconst;
void __gcov_merge_delta(gcov_type *counters, unsigned int n_counters) __attrconst;
void __gcov_merge_ior(gcov_type *counters, unsigned int n_counters) __attrconst;
void __gcov_merge_time_profile(gcov_type *counters, unsigned int n_counters) __attrconst;

void __gcov_init(void* f)
{
	(void)f;

	return;
}

void __gcov_merge_add(gcov_type *counters, unsigned int n_counters)
{
	(void)counters;
	(void)n_counters;

	return;
}

void __gcov_flush(void)
{
	return;
}

void __gcov_merge_single(gcov_type *counters, unsigned int n_counters)
{
	(void)counters;
	(void)n_counters;

	return;
}

void __gcov_merge_delta(gcov_type *counters, unsigned int n_counters)
{
	(void)counters;
	(void)n_counters;

	return;
}

void __gcov_merge_ior(gcov_type *counters, unsigned int n_counters)
{
	(void)counters;
	(void)n_counters;
	return;
}

void __gcov_merge_time_profile(gcov_type *counters, unsigned int n_counters)
{
	(void)counters;
	(void)n_counters;
}
