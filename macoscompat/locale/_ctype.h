/*
 * Copyright (c) 2000, 2005, 2008 Apple Inc. All rights reserved.
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
/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * This code is derived from software contributed to Berkeley by
 * Paul Borman at Krystal Technologies.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ctype.h	8.4 (Berkeley) 1/21/94
 */

#ifndef	__CTYPE_H_
#define __CTYPE_H_

#include "xlocale_private.h"
#include "darwin.h"
#include "runetype.h"

//Begin-Libc
/*
 * _EXTERNALIZE_CTYPE_INLINES_ is defined in locale/nomacros.c to tell us
 * to generate code for extern versions of all intermediate inline functions.
 */
#ifdef _EXTERNALIZE_CTYPE_INLINES_
#define _USE_CTYPE_INLINE_
#define __DARWIN_CTYPE_inline
#else /* !_EXTERNALIZE_CTYPE_INLINES_ */
//End-Libc
#define __DARWIN_CTYPE_inline		inline
//Begin-Libc
#endif /* !_EXTERNALIZE_CTYPE_INLINES_ */
//End-Libc

//Begin-Libc
/*
 * _EXTERNALIZE_CTYPE_INLINES_TOP_ is defined in locale/isctype.c to tell us
 * to generate code for extern versions of all top-level inline functions.
 */
#ifdef _EXTERNALIZE_CTYPE_INLINES_TOP_
#define _USE_CTYPE_INLINE_
#define __DARWIN_CTYPE_TOP_inline
#else /* !_EXTERNALIZE_CTYPE_INLINES_TOP_ */
//End-Libc
#define __DARWIN_CTYPE_TOP_inline	inline
//Begin-Libc
#endif /* _EXTERNALIZE_CTYPE_INLINES_TOP_ */
//End-Libc


#define	_CTYPE_A	0x00000100L		/* Alpha */
#define	_CTYPE_C	0x00000200L		/* Control */
#define	_CTYPE_D	0x00000400L		/* Digit */
#define	_CTYPE_G	0x00000800L		/* Graph */
#define	_CTYPE_L	0x00001000L		/* Lower */
#define	_CTYPE_P	0x00002000L		/* Punct */
#define	_CTYPE_S	0x00004000L		/* Space */
#define	_CTYPE_U	0x00008000L		/* Upper */
#define	_CTYPE_X	0x00010000L		/* X digit */
#define	_CTYPE_B	0x00020000L		/* Blank */
#define	_CTYPE_R	0x00040000L		/* Print */
#define	_CTYPE_I	0x00080000L		/* Ideogram */
#define	_CTYPE_T	0x00100000L		/* Special */
#define	_CTYPE_Q	0x00200000L		/* Phonogram */
#define	_CTYPE_SW0	0x20000000L		/* 0 width character */
#define	_CTYPE_SW1	0x40000000L		/* 1 width character */
#define	_CTYPE_SW2	0x80000000L		/* 2 width character */
#define	_CTYPE_SW3	0xc0000000L		/* 3 width character */
#define	_CTYPE_SWM	0xe0000000L		/* Mask for screen width data */
#define	_CTYPE_SWS	30			/* Bits to shift to get width */

__BEGIN_DECLS
unsigned long		___runetype(__darwin_ct_rune_t);
__darwin_ct_rune_t	___tolower(__darwin_ct_rune_t);
__darwin_ct_rune_t	___toupper(__darwin_ct_rune_t);
__END_DECLS

__DARWIN_CTYPE_inline int
__maskrune(__darwin_ct_rune_t _c, unsigned long _f)
{
    /* _CurrentRuneLocale.__runetype[_c] is __uint32_t
     * _f is unsigned long
     * ___runetype(_c) is unsigned long
     * retval is int
     */
    return (int)((_c < 0 || _c >= _CACHED_RUNES) ? (__uint32_t)___runetype(_c) :
                 __current_locale()->__lc_ctype->_CurrentRuneLocale.__runetype[_c]) & (__uint32_t)_f;
}

/*
 * We can't do what we do for __toupper_l() (check for ASCII first, then call
 * ___toupper_l() otherwise) because versions of ___toupper() before Tiger
 * assume c >= _CACHED_RUNES.  So we are stuck making __toupper() a routine
 * to hide the extended locale details, outside of Libc.
 */
__DARWIN_CTYPE_inline __darwin_ct_rune_t
__toupper(__darwin_ct_rune_t _c)
{
    return (_c < 0 || _c >= _CACHED_RUNES) ? ___toupper(_c) :
           __current_locale()->__lc_ctype->_CurrentRuneLocale.__mapupper[_c];
}

__DARWIN_CTYPE_inline __darwin_ct_rune_t
__tolower(__darwin_ct_rune_t _c)
{
    return (_c < 0 || _c >= _CACHED_RUNES) ? ___tolower(_c) :
           __current_locale()->__lc_ctype->_CurrentRuneLocale.__maplower[_c];
}

#endif /* !_CTYPE_H_ */
