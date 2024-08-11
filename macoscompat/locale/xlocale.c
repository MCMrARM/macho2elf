/*
 * Copyright (c) 2005, 2008 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#include "xlocale_private.h"
#include <errno.h>
#include <stddef.h>
#include <string.h>

#define NMBSTATET	10
#define C_LOCALE_INITIALIZER	{	\
	0, XPERMANENT,			\
	{}, {}, {}, {}, {},		\
	{}, {}, {}, {}, {},		\
	/*OS_UNFAIR_LOCK_INIT,*/		\
	XMAGIC,				\
	1, 0, 0, 0, 0, 0, 1, 1, 0,	\
	NULL,				\
	&_DefaultRuneXLocale,		\
}

static char C[] = "C";
static struct _xlocale __c_locale = C_LOCALE_INITIALIZER;
const locale_t _c_locale = (const locale_t)&__c_locale;
struct _xlocale __global_locale = C_LOCALE_INITIALIZER;
thread_local darwin_locale_t __current_locale_val;
