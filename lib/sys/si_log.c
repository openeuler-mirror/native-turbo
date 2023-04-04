/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "si_log.h"

static struct si_logs {
	uint32_t level;
} g_si_logs = {
    .level = SI_LOG_LEVEL_DEBUG,
};

void si_log_set_global_level(uint32_t level)
{
	g_si_logs.level = (uint32_t)level;
}

bool si_log_can_log(uint32_t level)
{
	if (level > g_si_logs.level)
		return false;

	return true;
}

int si_vlog(uint32_t level, const char *format, va_list ap)
{
	int ret;

	if (!si_log_can_log(level))
		return 0;

	ret = vprintf(format, ap);
	return ret;
}

int si_log(uint32_t level, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = si_vlog(level, format, ap);
	va_end(ap);
	return ret;
}
