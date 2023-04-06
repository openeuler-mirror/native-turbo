/* SPDX-License-Identifier: MulanPSL-2.0 */
#ifndef _SI_LOG_H
#define _SI_LOG_H

#include <stdarg.h>
#include <stdint.h>

// Definition of log levels
typedef enum LogLevel {
	SI_LOG_LEVEL_EMERG = 1,   /**< System is unusable.               */
	SI_LOG_LEVEL_ALERT,   /**< Action must be taken immediately. */
	SI_LOG_LEVEL_CRIT,    /**< Critical conditions.              */
	SI_LOG_LEVEL_ERR,     /**< Error conditions.                 */
	SI_LOG_LEVEL_WARNING, /**< Warning conditions.               */
	SI_LOG_LEVEL_NOTICE,  /**< Normal but significant condition. */
	SI_LOG_LEVEL_INFO,    /**< Informational.                    */
	SI_LOG_LEVEL_DEBUG,   /**< Debug-level messages.             */
} LogLevel;

void si_log_set_global_level(uint32_t level);
int si_log(uint32_t level, const char *format, ...);

// Log Macro Encapsulation
#define SI_LOG(level, format, ...)                                                           \
	do {                                                                                 \
		if (level >= 0) {                                                            \
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
