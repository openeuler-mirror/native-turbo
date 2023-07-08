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

#ifndef _SI_LOG_H
#define _SI_LOG_H

#include <stdint.h>

// Definition of log levels
typedef enum LogLevel {
	SI_LOG_LEVEL_EMERG = 1, /**< System is unusable.               */
	SI_LOG_LEVEL_ALERT,	/**< Action must be taken immediately. */
	SI_LOG_LEVEL_CRIT,	/**< Critical conditions.              */
	SI_LOG_LEVEL_ERR,	/**< Error conditions.                 */
	SI_LOG_LEVEL_WARNING,	/**< Warning conditions.               */
	SI_LOG_LEVEL_NOTICE,	/**< Normal but significant condition. */
	SI_LOG_LEVEL_INFO,	/**< Informational.                    */
	SI_LOG_LEVEL_DEBUG,	/**< Debug-level messages.             */
} LogLevel;

void si_log_set_global_level(uint32_t level);
int si_log(uint32_t level, const char *format, ...);

// compile will warning when var is not used, so compat it
// something is can not print in release version, so ignore SI_LOG_LEVEL_DEBUG
#ifdef DEBUG
#define SI_LOG_LEVEL_IGNORE 0
#else
#define SI_LOG_LEVEL_IGNORE SI_LOG_LEVEL_DEBUG
#endif

// Log Macro Encapsulation
#define SI_LOG(level, format, ...)                                                           \
	do {                                                                                 \
		if (level >= 0 && level != SI_LOG_LEVEL_IGNORE) {                            \
			si_log(level, "[%s:%d] " format, __func__, __LINE__, ##__VA_ARGS__); \
		}                                                                            \
	} while (0)

#define SI_LOG_EMERG(format, ...) SI_LOG(SI_LOG_LEVEL_EMERG, format, ##__VA_ARGS__)
#define SI_LOG_ALERT(format, ...) SI_LOG(SI_LOG_LEVEL_ALERT, format, ##__VA_ARGS__)
#define SI_LOG_CRIT(format, ...) SI_LOG(SI_LOG_LEVEL_CRIT, format, ##__VA_ARGS__)
#define SI_LOG_NOTICE(format, ...) SI_LOG(SI_LOG_LEVEL_NOTICE, format, ##__VA_ARGS__)
#define SI_LOG_INFO(format, ...) SI_LOG(SI_LOG_LEVEL_INFO, format, ##__VA_ARGS__)
#define SI_LOG_WARNING(format, ...) SI_LOG(SI_LOG_LEVEL_WARNING, format, ##__VA_ARGS__)
#define SI_LOG_ERR(format, ...) SI_LOG(SI_LOG_LEVEL_ERR, format, ##__VA_ARGS__)
#define SI_LOG_DEBUG(format, ...) SI_LOG(SI_LOG_LEVEL_DEBUG, format, ##__VA_ARGS__)
#endif /* _SI_LOG_H */
