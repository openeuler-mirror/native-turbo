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
