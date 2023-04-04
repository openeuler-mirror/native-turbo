/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <errno.h>
#include <execinfo.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "si_debug.h"

#define BACKTRACE_SIZE 256

/* dump the stack of the calling core */
void si_dump_stack(void)
{
	void *func[BACKTRACE_SIZE];
	char **symb = NULL;
	int size;

	size = backtrace(func, BACKTRACE_SIZE);
	symb = backtrace_symbols(func, size);

	if (symb == NULL)
		return;

	while (size > 0) {
		printf("%d: [%s]\n", size, symb[size - 1]);
		size--;
	}

	free(symb);
}

void __si_panic(const char *funcname, const char *format, ...)
{
	va_list ap;

	printf("panic in %s: ", funcname);
	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
	si_dump_stack();
	abort();
}
