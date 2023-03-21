/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "si_debug.h"

void __si_panic(const char *funcname, const char *format, ...)
{
	va_list ap;

	printf("panic in %s():\n", funcname);
	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
	abort();
}
