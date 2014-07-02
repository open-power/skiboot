/******************************************************************************
 * Copyright (c) 2004, 2008, 2012 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

void assert_fail(const char *msg)
{
	fputs("Assert fail:", stderr);
	fputs(msg, stderr);
	fputs("\n", stderr);
	abort();
}
