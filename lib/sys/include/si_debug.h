/* SPDX-License-Identifier: MulanPSL-2.0 */
#ifndef _SI_DEBUG_H
#define _SI_DEBUG_H

#include <stdarg.h>

// format must end with \n, force printf send to console
#define si_panic(...) si_panic_(__func__, __VA_ARGS__, "dummy")
#define si_panic_(func, format, ...) __si_panic(func, format, __VA_ARGS__)

void __si_panic(const char *funcname, const char *format, ...);

#endif /* _SI_DEBUG_H */
