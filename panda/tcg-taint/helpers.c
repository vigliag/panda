#include <stdio.h>
#include <stdint.h>

/*
* TODO(vigliag): I have no idea why I can't include tcg.h without including panda/plugin.h first
*/

#include "panda/plugin.h"
#include "tcg.h"

#include <dlfcn.h>
#include <string.h>

#include "panda/common.h"
#include "tcg-taint/callbacks.h"
#include "exec/helper-proto.h"

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

void helper_qtrace_reg2mem(target_ulong reg, target_ulong addr,
                            uint32_t size) {
  bool istmp = register_is_temp(reg);
  notify_taint_moveR2M(istmp, REG_IDX(istmp, reg), addr, size);
}

void helper_qtrace_mem2reg(target_ulong reg, target_ulong addr,
                                     uint32_t size) {
  bool istmp = register_is_temp(reg);
  notify_taint_moveM2R(addr, size, istmp, REG_IDX(istmp, reg));
}

void helper_qtrace_mov(target_ulong ret, target_ulong arg) {
  bool srctmp = register_is_temp(arg);
  bool dsttmp = register_is_temp(ret);
  notify_taint_moveR2R(srctmp, REG_IDX(srctmp, arg),
                       dsttmp, REG_IDX(dsttmp, ret));
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

  notify_taint_combineR2R(srctmp, REG_IDX(srctmp, src),
                          dsttmp, REG_IDX(dsttmp, dst));
}

/*
   Used for expressions like "A = B op C".
   labels(A) = labels(B) | labels(C)
 */
void helper_qtrace_combine3(target_ulong dst, target_ulong op1,
                                      target_ulong op2) {
  bool dsttmp = register_is_temp(dst);

  /* Clear destination first! */
  notify_taint_clearR(dsttmp, REG_IDX(dsttmp, dst));

  /* Combine op1 with dst */
  if (op1 != dst) {
    bool optmp = register_is_temp(op1);
    notify_taint_combineR2R(optmp,  REG_IDX(optmp, op1),
                            dsttmp, REG_IDX(dsttmp, dst));
  }

  /* Combine op2 with dst */
  if (op2 != dst) {
    bool optmp = register_is_temp(op2);
    notify_taint_combineR2R(optmp,  REG_IDX(optmp, op2),
                            dsttmp, REG_IDX(dsttmp, dst));
  }
}

void helper_qtrace_endtb(void) {
  notify_taint_endtb();
}

void helper_qtrace_deposit(target_ulong dst,
                                     target_ulong op1, target_ulong op2,
                                     unsigned int ofs, unsigned int len) {
  /* We currently support only byte-level deposit instructions, also because
     taint-tracking is performed at the byte-level */
  assert((ofs % 8) == 0 && (len % 8) == 0 && (ofs+len) <= 32);

  bool dsttmp = register_is_temp(dst);
  bool op2tmp = register_is_temp(op2);

  if (dst != op1) {
    bool op1tmp = register_is_temp(op1);
    notify_taint_moveR2R(op1tmp, REG_IDX(op1tmp, op1),
                         dsttmp, REG_IDX(dsttmp, dst));
  }

  notify_taint_moveR2R_offset(op2tmp, REG_IDX(op2tmp, op2), 0,
                              dsttmp, REG_IDX(dsttmp, dst), ofs/8,
                              len/8);
}

void helper_qtrace_assert(target_ulong reg, target_ulong istrue) {
    assert(!register_is_temp(reg));
    notify_taint_assert(REG_IDX(false, reg), istrue);
}
