#include <stdint.h>
#include <stdio.h>

/*
 * TODO(vigliag): I have no idea why I can't include tcg.h without including
 * panda/plugin.h first
 */

#include "panda/plugin.h"
#include "tcg.h"

#include <dlfcn.h>
#include <string.h>

#include "exec/helper-proto.h"
#include "panda/common.h"
#include "tcg-taint/callbacks.h"

/* Check if an index identifies a temporary register */
static inline bool register_is_temp(target_ulong idx) {
    return idx >= tcg_ctx.nb_globals;
}

/* Get the TCG index of the "idx"-th temporary register */
static inline target_ulong register_temp_index(target_ulong idx) {
    assert(register_is_temp(idx));
    return idx - tcg_ctx.nb_globals;
}

#define REG_IDX(istmp, r) ((istmp) ? register_temp_index(r) : (r))

void helper_qtrace_reg2mem(target_ulong reg, target_ulong addr, uint32_t size) {
    bool istmp = register_is_temp(reg);
    notify_taint_moveR2M(istmp, REG_IDX(istmp, reg), addr, size);
}

void helper_qtrace_micro_st(target_ulong reg, target_ulong addr,
                            uint32_t size) {
    notify_taint_micro_st(REG_IDX(true, reg), addr, size);
}

void helper_qtrace_mem2reg(target_ulong reg, target_ulong addr_reg, target_ulong addr, uint32_t size) {
    bool istmp = register_is_temp(reg);
    bool is_addr_tmp = register_is_temp(addr_reg);
    notify_taint_moveM2R(addr,is_addr_tmp, REG_IDX(is_addr_tmp, addr_reg), size, istmp, REG_IDX(istmp, reg));
}

void helper_qtrace_micro_ld(target_ulong reg, target_ulong addr,
                            uint32_t size) {
    notify_taint_micro_ld(REG_IDX(true, reg), addr, size);
}

void helper_qtrace_mov(target_ulong ret, target_ulong arg) {
    bool srctmp = register_is_temp(arg);
    bool dsttmp = register_is_temp(ret);
    notify_taint_moveR2R(srctmp, REG_IDX(srctmp, arg), dsttmp,
                         REG_IDX(dsttmp, ret));
}

void helper_qtrace_clearR(target_ulong reg) {
    bool istmp = register_is_temp(reg);
    notify_taint_clearR(istmp, REG_IDX(istmp, reg));
}

/*
   Used for expressions like "A = A op B".
   labels(A) = labels(A) | labels(B)
 */
void helper_qtrace_combine2(target_ulong dst, target_ulong src) {
    if (src == dst) {
        return;
    }

    bool dsttmp = register_is_temp(dst);
    bool srctmp = register_is_temp(src);

    notify_taint_combineR2R(srctmp, REG_IDX(srctmp, src), dsttmp,
                            REG_IDX(dsttmp, dst));
}

/*
   Used for expressions like "A = B op C".
   labels(A) = labels(B) | labels(C)
 */
void helper_qtrace_combine3(target_ulong dst, target_ulong op1,
                            target_ulong op2) {
    bool dsttmp = register_is_temp(dst);

    // Clear destination if it's not also one of the operands
    if( op1 != dst && op2 != dst){
        notify_taint_clearR(dsttmp, REG_IDX(dsttmp, dst));
    }

    /* Combine op1 with dst */
    if (op1 != dst) {
        bool optmp = register_is_temp(op1);
        notify_taint_combineR2R(optmp, REG_IDX(optmp, op1), dsttmp,
                                REG_IDX(dsttmp, dst));
    }

    /* Combine op2 with dst */
    if (op2 != dst) {
        bool optmp = register_is_temp(op2);
        notify_taint_combineR2R(optmp, REG_IDX(optmp, op2), dsttmp,
                                REG_IDX(dsttmp, dst));
    }
}

void helper_qtrace_endtb(void) { notify_taint_endtb(); }

void helper_qtrace_deposit(target_ulong dst, target_ulong op1, target_ulong op2,
                           unsigned int ofs, unsigned int len) {
    /* We currently support only byte-level deposit instructions, also because
       taint-tracking is performed at the byte-level

       WARNING(vigliag) there was an assertion here:

       ((ofs % 8) == 0 && (len % 8) == 0 && (ofs+len) <= 32)
       which is now failing with values such as dst=4, op1=4, op2=35, ofs=0,
       len=1

       NOTE: len=1 seems to be the result of this call:
       tcg_gen_deposit_tl(cpu_cc_src, cpu_cc_src, cpu_tmp4, ctz32(CC_C), 1);
       all the others have hardcoded values of multiple of 8

       I'm also changing this function to pass offset and len in bits when
       notifying for consistency with the other functions (it originally did a
       division)
     */

    bool dsttmp = register_is_temp(dst);
    bool op2tmp = register_is_temp(op2);

    if (dst != op1) {
        bool op1tmp = register_is_temp(op1);
        notify_taint_moveR2R(op1tmp, REG_IDX(op1tmp, op1), dsttmp,
                             REG_IDX(dsttmp, dst));
    }

    notify_taint_moveR2R_offset(op2tmp, REG_IDX(op2tmp, op2), 0, dsttmp,
                                REG_IDX(dsttmp, dst), ofs, len);
}

void helper_qtrace_assert(target_ulong reg, target_ulong istrue) {
    assert(!register_is_temp(reg));
    notify_taint_assert(REG_IDX(false, reg), istrue);
}
