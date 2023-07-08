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

#ifndef _DFE_RING_CORE_H_
#define _DFE_RING_CORE_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define __si_aligned(a) __attribute__((__aligned__(a)))
#define DFE_CACHE_LINE_SIZE 64
#define __si_cache_aligned __si_aligned(DFE_CACHE_LINE_SIZE)

struct si_ring_headtail {
	volatile uint32_t head; /**< prod/consumer head. */
	volatile uint32_t tail; /**< prod/consumer tail. */
};

struct si_ring {
	/** Ring producer status. */
	struct si_ring_headtail prod __si_cache_aligned;

	char pad0 __si_cache_aligned; /**< empty cache line */

	/** Ring consumer status. */
	struct si_ring_headtail cons __si_cache_aligned;

	char pad1 __si_cache_aligned; /**< empty cache line */

	// TODO: clean code, if we need name?
	char *name;
	int flags;
	uint32_t size;
	uint32_t mask;

	char pad2 __si_cache_aligned; /**< empty cache line */
};

#ifdef __cplusplus
}
#endif

#endif /* _DFE_RING_CORE_H_ */
