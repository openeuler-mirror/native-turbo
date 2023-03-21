/* SPDX-License-Identifier: MulanPSL-2.0 */
#ifndef _SI_LOG_H
#define _SI_LOG_H

#include <stdarg.h>
#include <stdint.h>

#define SI_LOG_EMERG 1U	  /**< System is unusable.               */
#define SI_LOG_ALERT 2U	  /**< Action must be taken immediately. */
#define SI_LOG_CRIT 3U	  /**< Critical conditions.              */
#define SI_LOG_ERR 4U	  /**< Error conditions.                 */
#define SI_LOG_WARNING 5U /**< Warning conditions.               */
#define SI_LOG_NOTICE 6U  /**< Normal but significant condition. */
#define SI_LOG_INFO 7U	  /**< Informational.                    */
#define SI_LOG_DEBUG 8U	  /**< Debug-level messages.             */

void si_log_set_global_level(uint32_t level);
int si_log(uint32_t level, const char *format, ...);
#define si_log_info(...) si_log(SI_LOG_INFO, ##__VA_ARGS__)
#define si_log_debug(...) si_log(SI_LOG_DEBUG, ##__VA_ARGS__)

#endif /* _SI_LOG_H */
