/*
 * memcpy - copy memory area
 *
 * Copyright (c) 2012-2022, Arm Limited.
 * SPDX-License-Identifier: MIT OR Apache-2.0 WITH LLVM-exception
 */

/* Assumptions:
 *
 * ARMv8-a, AArch64, unaligned accesses.
 *
 */

        .arch armv8.2-a+crypto+crc
        .file   "memcpy.c"
        .text
        .align  2
        .p2align 4,,11
        .global __memcpy_aarch64
        .hidden __memcpy_aarch64
        .type   __memcpy_aarch64, %function
__memcpy_aarch64:
.LFB4277:
        .cfi_startproc
        sub     sp, sp, #32 
        .cfi_def_cfa_offset 32
        adrp    x3, :got:__stack_chk_guard
        stp     x29, x30, [sp, 16] 
        .cfi_offset 29, -16 
        .cfi_offset 30, -8
        add     x29, sp, 16
        ldr     x3, [x3, #:got_lo12:__stack_chk_guard]
        ldr     x4, [x3]
        str     x4, [sp, 8]
        mov     x4, 0
        cmp     x2, 255 
        bls     .L11
        sub     x6, x2, #256
        mov     x3, x1
        and     x6, x6, -256
        mov     x4, x0
        add     x6, x6, 256 
        add     x5, x0, x6
        .p2align 3,,7
.L3:
        ldp     q23, q22, [x3]
        ldp     q21, q20, [x3, 32] 
        ldp     q19, q18, [x3, 64] 
        ldp     q17, q16, [x3, 96] 
        ldp     q7, q6, [x3, 128]
        ldp     q5, q4, [x3, 160]
        ldp     q3, q2, [x3, 192]
        ldp     q1, q0, [x3, 224]
        prfm    PLDL1STRM, [x3, 512]
        prfm    PLDL1STRM, [x3, 576]
        prfm    PLDL1STRM, [x3, 640]
        prfm    PLDL1STRM, [x3, 704]
        prfm    PLDL2KEEP, [x3, 1024]
        prfm    PLDL2KEEP, [x3, 1088]
        prfm    PLDL2KEEP, [x3, 1152]
        prfm    PLDL2KEEP, [x3, 1216]
        add     x3, x3, 256 
        stp     q23, q22, [x4]
        stp     q21, q20, [x4, 32] 
        stp     q19, q18, [x4, 64] 
        stp     q17, q16, [x4, 96] 
        stp     q7, q6, [x4, 128]
        stp     q5, q4, [x4, 160]
        stp     q3, q2, [x4, 192]
        stp     q1, q0, [x4, 224]
        add     x4, x4, 256
        cmp     x4, x5
        bne     .L3
        add     x1, x1, x6
        and     x2, x2, 255
.L2:
        cmp     x2, 127
        bls     .L4
        ldp     q7, q6, [x1]
        sub     x2, x2, #128
        ldp     q5, q4, [x1, 32]
        ldp     q3, q2, [x1, 64]
        ldp     q1, q0, [x1, 96]
        prfm    PLDL1STRM, [x1, 512]
        prfm    PLDL1STRM, [x1, 576]
        prfm    PLDL2KEEP, [x1, 1024]
        prfm    PLDL2KEEP, [x1, 1088]
        add     x1, x1, 128
        stp     q7, q6, [x5]
        stp     q5, q4, [x5, 32]
        stp     q3, q2, [x5, 64]
        stp     q1, q0, [x5, 96]
        add     x5, x5, 128
.L4:
        cmp     x2, 63
        bls     .L5
        ldp     q3, q2, [x1]
        sub     x2, x2, #64
        ldp     q1, q0, [x1, 32]
        add     x1, x1, 64
        stp     q3, q2, [x5]
        stp     q1, q0, [x5, 32]
        add     x5, x5, 64
.L5:
        cmp     x2, 15
        bls     .L6
        mov     x3, 0
.L7:
        ldr     q0, [x1, x3]
        str     q0, [x5, x3]
        add     x3, x3, 16
        sub     x4, x2, x3
        cmp     x4, 15
        bhi     .L7
        sub     x3, x2, #16
        and     x2, x2, 15
        and     x3, x3, -16
        add     x3, x3, 16
        add     x5, x5, x3
        add     x1, x1, x3
.L6:
        cbz     x2, .L8
        mov     x3, 0
        .p2align 3,,7
.L9:
        ldrb    w4, [x1, x3]
        strb    w4, [x5, x3]
        add     x3, x3, 1
        cmp     x3, x2
        bne     .L9
.L8:
        adrp    x1, :got:__stack_chk_guard
        ldr     x1, [x1, #:got_lo12:__stack_chk_guard]
        ldr     x2, [sp, 8]
        ldr     x3, [x1]
        subs    x2, x2, x3
        mov     x3, 0
        bne     .L20
        ldp     x29, x30, [sp, 16]
        add     sp, sp, 32
        .cfi_remember_state
        .cfi_restore 29
        .cfi_restore 30
        .cfi_def_cfa_offset 0
        ret
        .p2align 2,,3
.L11:
        .cfi_restore_state
        mov     x5, x0
        b       .L2
.L20:
        bl      __stack_chk_fail
        .cfi_endproc
.LFE4277:
        .size   __memcpy_aarch64, .-__memcpy_aarch64
        .ident  "GCC: (GNU) 10.3.1"
        .section        .note.GNU-stack,"",@progbits
        .global __memmove_aarch64
        .set    __memmove_aarch64, __memcpy_aarch64