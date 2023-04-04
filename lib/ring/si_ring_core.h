/* SPDX-License-Identifier: MulanPSL-2.0 */

#ifndef _DFE_RING_CORE_H_
#define _DFE_RING_CORE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

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

	// TODO: if we need name?
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
