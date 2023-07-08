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

#ifndef _SI_COMMON_H
#define _SI_COMMON_H

#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough \
	do {        \
	} while (0) /* fallthrough */
#endif

#define SI_MIN(a, b)                \
	__extension__({             \
		typeof(a) _a = (a); \
		typeof(b) _b = (b); \
		_a < _b ? _a : _b;  \
	})

#define SI_MAX(a, b)                \
	__extension__({             \
		typeof(a) _a = (a); \
		typeof(b) _b = (b); \
		_a > _b ? _a : _b;  \
	})

#define min(a, b) SI_MIN(a, b)
#define max(a, b) SI_MAX(a, b)

#define ALIGN(x, a) (((x) + ((typeof(x))(a)-1)) & ~((typeof(x))(a)-1))

#define SI_CACHE_LINE_SIZE 64
#define SI_HUGEPAGE_ALIGN_SIZE 0x200000

// aarch64 header file is not define PAGE_SIZE
#ifndef PAGE_SHIFT
#define PAGE_SHIFT              12
#endif
#ifndef PAGE_SIZE
#define PAGE_SIZE               (1UL << PAGE_SHIFT)
#endif
#ifndef PAGE_MASK
#define PAGE_MASK               (~(PAGE_SIZE-1))
#endif

typedef int (*si_cmp_func)(const void *a, const void *b);

const char *si_basename(const char *path);

#endif /* _SI_COMMON_H */
