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

#ifndef _SI_TEST_H
#define _SI_TEST_H

#include <stdio.h>

#define SI_TEST_ASSERT(cond, msg, ...)                                                                      \
	do {                                                                                                \
		if (!(cond)) {                                                                              \
			printf("TEST_ASSERT %s : %d failed: " msg "\n", __func__, __LINE__, ##__VA_ARGS__); \
			return -1;                                                                          \
		}                                                                                           \
	} while (0)

#define SI_TEST_ASSERT_FAIL(val, msg, ...) SI_TEST_ASSERT(val != 0, msg, ##__VA_ARGS__)

#define TEST_ASSERT SI_TEST_ASSERT
#define TEST_ASSERT_FAIL SI_TEST_ASSERT_FAIL

#endif /* _SI_TEST_H */
