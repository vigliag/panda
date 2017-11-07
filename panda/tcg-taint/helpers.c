#include "tcg-op.h"
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

void helper_qtrace_reg2mem(target_ulong reg, target_ulong addr,
                            int size) {
  bool istmp = register_is_temp(reg);
  notify_taint_moveR2M(istmp, REG_IDX(istmp, reg), addr, size);
}

void helper_qtrace_mem2reg(target_ulong reg, target_ulong addr,
                                     int size) {
  bool istmp = register_is_temp(reg);
  notify_taint_moveM2R(addr, size, istmp, REG_IDX(istmp, reg));
}

void helper_qtrace_mem2reg(target_ulong reg, target_ulong addr,
                            int size) {
  bool istmp = register_is_temp(reg);
  notify_taint_moveM2R(addr, size, istmp, REG_IDX(istmp, reg));
}

void helper_qtrace_mem2reg_i64(int64_t reg, target_ulong addr,
                            int size) {
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

void helper_tcg_gen_qtrace_assert(target_ulong reg, target_ulong istrue) {
    assert(!register_is_temp(reg));
    notify_taint_assert(REG_IDX(false, reg), istrue);
}
