/* SPDX-License-Identifier: MulanPSL-2.0 */

#include "dfe_ring.h"

unsigned int
dfe_ring_enqueue_burst(struct dfe_ring *r, void * const *obj_table, unsigned int n)
{
	(void)r;
	(void)obj_table;
	(void)n;
	return 0;
}

unsigned int
dfe_ring_dequeue_burst(struct dfe_ring *r, void **obj_table, unsigned int n)
{
	(void)r;
	(void)obj_table;
	(void)n;
	return 0;
}

