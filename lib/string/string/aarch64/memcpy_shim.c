#include <stddef.h>

void *__memcpy_aarch64_simd(void * __restrict, const void * __restrict, size_t);

void *memcpy(void *dst, const void *src, size_t n) {
    return __memcpy_aarch64_simd(dst, src, n); 
}

/* 建议一并覆盖 Fortify 路径 */
void *__memcpy_chk(void *dst, const void *src, size_t n, size_t dstlen) {
    (void)dstlen;
    return memcpy(dst, src, n); 
}