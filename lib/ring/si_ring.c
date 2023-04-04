/* SPDX-License-Identifier: MulanPSL-2.0 */

#include "si_ring.h"

unsigned int
si_ring_enqueue_burst(struct si_ring *r, void *const *obj_table, unsigned int n)
{
	(void)r;
	(void)obj_table;
	(void)n;
	return 0;
}

unsigned int
si_ring_dequeue_burst(struct si_ring *r, void **obj_table, unsigned int n)
{
	(void)r;
	(void)obj_table;
	(void)n;
	return 0;
}
