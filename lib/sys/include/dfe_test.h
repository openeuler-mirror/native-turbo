/* SPDX-License-Identifier: MulanPSL-2.0 */
#ifndef _DFE_TEST_H
#define _DFE_TEST_H

#include <stdio.h>

#define DFE_TEST_ASSERT(cond, msg, ...)                                                                     \
	do {                                                                                                \
		if (!(cond)) {                                                                              \
			printf("TEST_ASSERT %s : %d failed: " msg "\n", __func__, __LINE__, ##__VA_ARGS__); \
			return -1;                                                                          \
		}                                                                                           \
	} while (0)

#define DFE_TEST_ASSERT_FAIL(val, msg, ...) DFE_TEST_ASSERT(val != 0, msg, ##__VA_ARGS__)

#define TEST_ASSERT DFE_TEST_ASSERT
#define TEST_ASSERT_FAIL DFE_TEST_ASSERT_FAIL

#endif /* _DFE_TEST_H */
