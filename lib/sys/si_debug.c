// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
//
// native-turbo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

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

	if (symb == NULL) {
		return;
	}

	for (int i = 0; i < size; i++) {
		printf("%d: [%s]\n", i, symb[i]);
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
