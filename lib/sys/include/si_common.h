/* SPDX-License-Identifier: MulanPSL-2.0 */
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

#define PAGE_SHIFT 12
#define PAGE_MASK (~((1UL << PAGE_SHIFT) - 1))

typedef int (*si_cmp_func)(const void *a, const void *b);

const char *si_basename(const char *path);

#endif /* _SI_COMMON_H */
