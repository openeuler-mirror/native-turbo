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

#ifndef _DFE_RING_H_
#define _DFE_RING_H_

#include <si_ring_core.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Tradeoff: caller no need know free space, caller used list to store left object
 */
unsigned int si_ring_enqueue_burst(struct si_ring *r,
		void *const *obj_table, unsigned int n);

/*
 * Tradeoff: caller no need know available object, caller just loop to work all
 */
unsigned int si_ring_dequeue_burst(struct si_ring *r,
		void **obj_table, unsigned int n);

#ifdef __cplusplus
}
#endif

#endif /* _DFE_RING_H_ */
