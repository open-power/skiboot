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


#ifndef __FSPMDST_H
#define __FSPMDST_H

/* Dump section type */
#define DUMP_SECTION_CONSOLE	0x01
#define DUMP_SECTION_HBRT_LOG	0x02

/*
 * Sapphire Memory Dump Source Table
 *
 * Format of this table is same as Memory Dump Source Table (MDST)
 * defined in HDAT spec.
 */
struct dump_mdst_table {
	uint64_t	addr;
	uint32_t	type; /* DUMP_SECTION_* */
	uint32_t	size;
};

#endif	/* __FSPMDST_H */
