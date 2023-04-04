/* SPDX-License-Identifier: MulanPSL-2.0 */

#ifndef _DFE_RING_H_
#define _DFE_RING_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <si_ring_core.h>

/*
 * Tradeoff: caller no need know free space, caller used list to store left object
 */
unsigned int
si_ring_enqueue_burst(struct si_ring *r, void *const *obj_table, unsigned int n);

/*
 * Tradeoff: caller no need know available object, caller just loop to work all
 */
unsigned int
si_ring_dequeue_burst(struct si_ring *r, void **obj_table, unsigned int n);

#ifdef __cplusplus
}
#endif

#endif /* _DFE_RING_H_ */
