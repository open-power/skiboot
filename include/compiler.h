// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __COMPILER_H
#define __COMPILER_H

#ifndef __ASSEMBLY__

#include <stddef.h>

/* Macros for various compiler bits and pieces */
#define __packed		__attribute__((packed))
#define __align(x)		__attribute__((__aligned__(x)))
#define __unused		__attribute__((unused))
#define __used			__attribute__((used))
#define __section(x)		__attribute__((__section__(x)))
#define __noreturn		__attribute__((noreturn))
/* not __const as this has a different meaning (const) */
#define __attrconst		__attribute__((const))
#define __warn_unused_result	__attribute__((warn_unused_result))
#define __noinline		__attribute__((noinline))

/*
 * GCC 15 introduces errors for "unterminated-string-initialization", mark
 * character arrays that are not intended to be null-terminated as
 * 'nonstring', such as eye-catchers
 */
#define __nonstring		__attribute((nonstring))

#if 0 /* Provided by gcc stddef.h */
#define offsetof(type,m)	__builtin_offsetof(type,m)
#endif

#define __nomcount		__attribute__((no_instrument_function))

/* Compiler barrier */
static inline void barrier(void)
{
	asm volatile("" : : : "memory");
}

#endif /* __ASSEMBLY__ */

/* Stringification macro */
#define __tostr(x)	#x
#define tostr(x)	__tostr(x)


#if __GNUC__ >= 11
/* Compiler workaround to avoid compiler optimization warnings
 * when assigning constant address to pointer and using memory
 * functions such as memcpy and  memset
 */
#define skiboot_constant_addr          volatile
#else
#define skiboot_constant_addr
#endif


#endif /* __COMPILER_H */
