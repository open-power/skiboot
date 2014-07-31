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

/*
 * Console Log routines
 * Wraps libc and console lower level functions
 * does fancy-schmancy things like timestamps and priorities
 * Doesn't make waffles.
 */

#include "skiboot.h"
#include "unistd.h"
#include "stdio.h"
#include "console.h"
#include "timebase.h"

static int vprlog(int log_level, const char *fmt, va_list ap)
{
	int count;
	char buffer[320];

	count = snprintf(buffer, sizeof(buffer), "[%lu,%d] ",
			 mftb(), log_level);
	count+= vsnprintf(buffer+count, sizeof(buffer)-count, fmt, ap);

	console_write((log_level > PR_NOTICE) ? false : true, buffer, count);

	return count;
}

/* we don't return anything as what on earth are we going to do
 * if we actually fail to print a log message? Print a log message about it?
 * Callers shouldn't care, prlog and friends should do something generically
 * sane in such crazy situations.
 */
void prlog(int log_level, const char* fmt, ...)
{
	va_list ap;
    
	va_start(ap, fmt);
	vprlog(log_level, fmt, ap);
	va_end(ap);
}

int printf(const char* fmt, ...)
{
	int count;
	va_list ap;
    
	va_start(ap, fmt);
	count = vprlog(PR_PRINTF, fmt, ap);
	va_end(ap);
    
	return count;
}
