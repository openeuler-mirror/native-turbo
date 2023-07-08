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

#include "si_ring.h"

unsigned int si_ring_enqueue_burst(struct si_ring *r,
		void *const *obj_table, unsigned int n)
{
	(void)r;
	(void)obj_table;
	(void)n;
	return 0;
}

unsigned int si_ring_dequeue_burst(struct si_ring *r,
		void **obj_table, unsigned int n)
{
	(void)r;
	(void)obj_table;
	(void)n;
	return 0;
}
