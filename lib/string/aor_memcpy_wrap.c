// aor_memcpy_wrap.c — 拦截 memcpy/memcpy_s；尽可能调用 __memcpy_aarch64_simd（无任何日志/IO）
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef __errno_t_defined
typedef int errno_t;
#endif
typedef size_t rsize_t;

typedef void *(*memcpy_fn)(void *, const void *, size_t);
typedef void *(*memmove_fn)(void *, const void *, size_t);
typedef void *(*simd_memcpy_fn)(void *, const void *, size_t);

static memcpy_fn      real_memcpy  = NULL;
static memmove_fn     real_memmove = NULL;
static simd_memcpy_fn simd_memcpy  = NULL;
static int            inited       = 0;

#define MEMCPY_REP_TYPE "__memcpy_aarch64_simd"

static inline int overlap(const void *d, const void *s, size_t n) {
    uintptr_t D=(uintptr_t)d, S=(uintptr_t)s;
    return (S < D + n) && (D < S + n); 
}

/* 具备 memmove 语义的原始拷贝，避免任何 libc 调用，防递归 */
static inline void *raw_move(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char*)dst;
    const unsigned char *s = (const unsigned char*)src;
    if (d == s || n == 0) return dst;
    if (d < s || d >= s + n) {
        while (n >= sizeof(uint64_t)) { *(uint64_t*)d = *(const uint64_t*)s; d += 8; s += 8; n -= 8; }
        while (n--) { *d++ = *s++; }
    } else {
        d += n; s += n;
        while (n >= sizeof(uint64_t)) { d -= 8; s -= 8; *(uint64_t*)d = *(const uint64_t*)s; n -= 8; }
        while (n--) { *--d = *--s; }
    }   
    return dst;
}

/* 解析 __memcpy_aarch64_simd */
static simd_memcpy_fn resolve_simd(void) {
    simd_memcpy_fn fn = (simd_memcpy_fn)dlsym(RTLD_DEFAULT, MEMCPY_REP_TYPE);
    if (fn) return fn; 

    const char* so_path = getenv("AOR_STRINGLIB"); // 可显式指定 libstringlib.so 路径
    if (so_path && *so_path) {
        void* h = dlopen(so_path, RTLD_NOW | RTLD_LOCAL);
        if (h) {
            fn = (simd_memcpy_fn)dlsym(h, MEMCPY_REP_TYPE);
            if (fn) return fn; 
        }   
    }   
    void* h2 = dlopen("libstringlib.so", RTLD_NOW | RTLD_LOCAL);
    if (h2) {
        fn = (simd_memcpy_fn)dlsym(h2, MEMCPY_REP_TYPE);
        if (fn) return fn; 
    }   
    return NULL;
}

__attribute__((constructor))
static void init_wrap(void){
    real_memcpy  = (memcpy_fn)dlsym(RTLD_NEXT, "memcpy");
    real_memmove = (memmove_fn)dlsym(RTLD_NEXT, "memmove");
    simd_memcpy  = resolve_simd();
    inited = 1;
}

__attribute__((destructor))
static void fini_wrap(void){
    /* 无资源需释放 */
}

/* ============= 1) 拦截 libc memcpy ============= */
__attribute__((visibility("default")))
void *memcpy(void *dst, const void *src, size_t n) {
    if (!n || dst == src) return dst;
    if (!inited) return raw_move(dst, src, n);

    if (overlap(dst, src, n)) {
        return real_memmove ? real_memmove(dst, src, n) : raw_move(dst, src, n);
    }
    if (simd_memcpy) {
        return simd_memcpy(dst, src, n);
    }
    return real_memcpy ? real_memcpy(dst, src, n) : raw_move(dst, src, n);
}

/* ============= 2) 拦截 C11 memcpy_s（小写） ============= */
__attribute__((visibility("default")))
errno_t memcpy_s(void *dst, rsize_t dstsz, const void *src, rsize_t n) {
    if (!dst || !src) return 22;   // EINVAL
    if (n > dstsz)     return 34;  // ERANGE
    if (n == 0 || dst == src) return 0;

    if (!inited) { raw_move(dst, src, n); return 0; }

    if (overlap(dst, src, n)) {
        if (real_memmove) real_memmove(dst, src, n);
        else raw_move(dst, src, n);
        return 0;
    }
    if (simd_memcpy) {
        simd_memcpy(dst, src, n);
        return 0;
    }
    if (real_memcpy) real_memcpy(dst, src, n);
    else raw_move(dst, src, n);
    return 0;
}