/* SPDX-License-Identifier: MulanPSL-2.0 */
#ifndef _DFE_COMMON_H
#define _DFE_COMMON_H

#define DFE_MIN(a, b)               \
	__extension__({             \
		typeof(a) _a = (a); \
		typeof(b) _b = (b); \
		_a < _b ? _a : _b;  \
	})

#define DFE_MAX(a, b)               \
	__extension__({             \
		typeof(a) _a = (a); \
		typeof(b) _b = (b); \
		_a > _b ? _a : _b;  \
	})

#define min(a, b) DFE_MIN(a, b)
#define max(a, b) DFE_MAX(a, b)

#define ALIGN(x, a) (((x) + ((typeof(x))(a)-1)) & ~((typeof(x))(a)-1))

#define DFE_CACHE_LINE_SIZE 64

typedef int (*dfe_cmp_func)(const void *a, const void *b);

#endif /* _DFE_COMMON_H */
