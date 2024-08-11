#ifndef _DARWIN_H_
#define _DARWIN_H_

#include <sys/cdefs.h>

__BEGIN_DECLS

typedef wchar_t __darwin_wchar_t;

typedef union {
    char		__mbstate8[128];
    long long	_mbstateL;
} __darwin_mbstate_u;

typedef __darwin_mbstate_u	__darwin_mbstate_t;
typedef __darwin_mbstate_t darwin_mbstate_t;

typedef int	__darwin_ct_rune_t;

#define __unused __attribute__((unused))

__END_DECLS

#endif /* _DARWIN_PRIVATE_H_ */
