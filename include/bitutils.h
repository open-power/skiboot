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

#ifndef __BITUTILS_H
#define __BITUTILS_H

/* PPC bit number conversion */
#ifdef __ASSEMBLY__
#define PPC_BIT(bit)		(0x8000000000000000 >> (bit))
#define PPC_BIT32(bit)		(0x80000000 >> (bit))
#define PPC_BIT8(bit)		(0x80 >> (bit))
#else
#define PPC_BIT(bit)		(0x8000000000000000UL >> (bit))
#define PPC_BIT32(bit)		(0x80000000UL >> (bit))
#define PPC_BIT8(bit)		(0x80UL >> (bit))
#endif
#define PPC_BITMASK(bs,be)	((PPC_BIT(bs) - PPC_BIT(be)) | PPC_BIT(bs))
#define PPC_BITMASK32(bs,be)	((PPC_BIT32(bs) - PPC_BIT32(be))|PPC_BIT32(bs))
#define PPC_BITLSHIFT(be)	(63 - (be))
#define PPC_BITLSHIFT32(be)	(31 - (be))

/*
 * PPC bitmask field manipulation
 */

/* Extract field fname from val */
#define GETFIELD(fname, val)			\
	(((val) & fname##_MASK) >> fname##_LSH)

/* Set field fname of oval to fval
 * NOTE: oval isn't modified, the combined result is returned
 */
#define SETFIELD(fname, oval, fval)			\
	(((oval) & ~fname##_MASK) | \
	 ((((typeof(oval))(fval)) << fname##_LSH) & fname##_MASK))

#endif /* __BITUTILS_H */
