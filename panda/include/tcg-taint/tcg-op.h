//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#include "exec/helper-gen.h"
#include "tcg-taint/tcg-taint.h"

//#if TARGET_LONG_BITS != 32
//#error 64-bit targets are not supported (yet)
//#endif

#define QTRACE_INSTRUMENT_START()                                              \
    {                                                                          \
        if (likely(!qtrace_taint_instrumentation_enabled)) {                   \
            return;                                                            \
        }                                                                      \
        if (unlikely(qtrace_in_instrumentation)) {                             \
            return;                                                            \
        }                                                                      \
        qtrace_in_instrumentation = true;                                      \
    }

#define QTRACE_INSTRUMENT_END()                                                \
    { qtrace_in_instrumentation = false; }

#define QTRACE_ASSERT_TAINTED 0xabadb00b
#define QTRACE_ASSERT_NOT_TAINTED (QTRACE_ASSERT_TAINTED + 1)

/*
 * Vigliag:
 * NOTE: what he's doing here, is taking the identifiers of the registers,
 * and casting them to constants/immediates before passing them to helpers.
 * Helpers are normally passed the content of the registers, so we create
 * a new temporary register holding the register ID we are interested in
 */

static inline void tcg_gen_qtrace_endtb(void) {
    QTRACE_INSTRUMENT_START();

    gen_helper_qtrace_endtb();

    QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_qemu_ld(TCGv arg, TCGv addr, int size) {
    QTRACE_INSTRUMENT_START();

    // arg is the identifier of a register (an integer), we need this integer
    // value, not the content of the register

    // GET_TCGV_I32 casts the TCGv back to an integer
    // tcg_const_i32 creates a temporary register with that integer value, so we
    // can pass the index to the helper  note we pass "addr" directly, as it is a
    // real register, whose value we care about at runtime

    TCGv_i32 argidx = tcg_const_i32(GET_TCGV_I32(arg));
    TCGv_i32 ldsize = tcg_const_i32(size);

    gen_helper_qtrace_mem2reg(argidx, addr, ldsize);

    tcg_temp_free_i32(argidx);
    tcg_temp_free_i32(ldsize);

    QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_qemu_ld_i64(TCGv_i64 arg, TCGv addr,
                                              int size) {
    QTRACE_INSTRUMENT_START();

    TCGv_i32 argidx = tcg_const_i32(GET_TCGV_I64(arg));
    TCGv_i32 ldsize = tcg_const_i32(size);

    gen_helper_qtrace_mem2reg(argidx, addr, ldsize);

    tcg_temp_free_i32(argidx);
    tcg_temp_free_i32(ldsize);

    QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_qemu_micro_ld(TCGv_i64 ret, TCGv_ptr envptr,
                                                tcg_target_long offset,
                                                int size) {
    (void)envptr;
    QTRACE_INSTRUMENT_START();

    TCGv_i32 argidx = tcg_const_i32(GET_TCGV_I64(ret));
    TCGv_i32 ldsize = tcg_const_i32(size);
    TCGv_i32 offsetval = tcg_const_i32(offset);

    gen_helper_qtrace_micro_ld(argidx, offsetval, ldsize);

    tcg_temp_free_i32(argidx);
    tcg_temp_free_i32(ldsize);
    tcg_temp_free_i32(offsetval);

    QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_qemu_st(TCGv arg, TCGv addr, int size) {
    QTRACE_INSTRUMENT_START();

    TCGv_i32 argidx = tcg_const_i32(GET_TCGV_I32(arg));
    TCGv_i32 stsize = tcg_const_i32(size);

    gen_helper_qtrace_reg2mem(argidx, addr, stsize);

    tcg_temp_free_i32(argidx);
    tcg_temp_free_i32(stsize);

    QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_qemu_st_i64(TCGv_i64 arg, TCGv addr,
                                              int size) {
    QTRACE_INSTRUMENT_START();

    TCGv_i32 argidx = tcg_const_i32(GET_TCGV_I64(arg));
    TCGv_i32 stsize = tcg_const_i32(size);

    gen_helper_qtrace_reg2mem(argidx, addr, stsize);

    tcg_temp_free_i32(argidx);
    tcg_temp_free_i32(stsize);

    QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_qemu_micro_st(TCGv_i64 arg1, TCGv_ptr envptr,
                                                tcg_target_long offset,
                                                int size) {
    (void)envptr;
    QTRACE_INSTRUMENT_START();

    TCGv_i32 argidx = tcg_const_i32(GET_TCGV_I64(arg1));
    TCGv_i32 stsize = tcg_const_i32(size);
    TCGv_i32 offsetaddr = tcg_const_i32(offset);

    gen_helper_qtrace_micro_st(argidx, offsetaddr, stsize);

    tcg_temp_free_i32(argidx);
    tcg_temp_free_i32(stsize);
    tcg_temp_free_i32(offsetaddr);

    QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_mov(TCGv_i32 ret, TCGv_i32 arg) {
    QTRACE_INSTRUMENT_START();

    TCGv_i32 retidx = tcg_const_i32(GET_TCGV_I32(ret));
    TCGv_i32 argidx = tcg_const_i32(GET_TCGV_I32(arg));

    gen_helper_qtrace_mov(retidx, argidx);

    tcg_temp_free_i32(argidx);
    tcg_temp_free_i32(retidx);

    QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_clearR(TCGv_i32 ret) {
    QTRACE_INSTRUMENT_START();

    TCGv_i32 retidx = tcg_const_i32(GET_TCGV_I32(ret));

    gen_helper_qtrace_clearR(retidx);

    tcg_temp_free_i32(retidx);

    QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_combine2(TCGOpcode opc, TCGv_i32 ret,
                                           TCGv_i32 arg) {
    (void)opc;

    QTRACE_INSTRUMENT_START();
    assert(!TCGV_EQUAL_I32(ret, arg));

    TCGv_i32 retidx = tcg_const_i32(GET_TCGV_I32(ret));
    TCGv_i32 argidx = tcg_const_i32(GET_TCGV_I32(arg));
    // TCGv_i32 opcode = tcg_const_i32(opc);

    gen_helper_qtrace_combine2(retidx, argidx);

    tcg_temp_free_i32(retidx);
    tcg_temp_free_i32(argidx);

    QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_combine3(TCGOpcode opc, TCGv_i32 ret,
                                           TCGv_i32 arg1, TCGv_i32 arg2) {
    (void)opc;
    QTRACE_INSTRUMENT_START();

    // WARNING(vigliag) CHECK(vigliag)
    // assertion failing TCGV_EQUAL_I32(arg1, arg2)
    // I don't understand why this check, and why it is different
    // from the check above. (which compared arg with ret)

    // assert(TCGV_EQUAL_I32(arg1, arg2))

    TCGv_i32 retidx = tcg_const_i32(GET_TCGV_I32(ret));
    TCGv_i32 arg1idx = tcg_const_i32(GET_TCGV_I32(arg1));
    TCGv_i32 arg2idx = tcg_const_i32(GET_TCGV_I32(arg2));

    gen_helper_qtrace_combine3(retidx, arg1idx, arg2idx);

    tcg_temp_free_i32(retidx);
    tcg_temp_free_i32(arg1idx);
    tcg_temp_free_i32(arg2idx);

    QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_deposit(TCGv_i32 ret, TCGv_i32 arg1,
                                          TCGv_i32 arg2, unsigned int ofs,
                                          unsigned int len) {
    QTRACE_INSTRUMENT_START();

    TCGv_i32 retidx = tcg_const_i32(GET_TCGV_I32(ret));
    TCGv_i32 arg1idx = tcg_const_i32(GET_TCGV_I32(arg1));
    TCGv_i32 arg2idx = tcg_const_i32(GET_TCGV_I32(arg2));
    TCGv_i32 ofsval = tcg_const_i32(ofs);
    TCGv_i32 lenval = tcg_const_i32(len);

    gen_helper_qtrace_deposit(retidx, arg1idx, arg2idx, ofsval, lenval);

    tcg_temp_free_i32(retidx);
    tcg_temp_free_i32(arg1idx);
    tcg_temp_free_i32(arg2idx);
    tcg_temp_free_i32(ofsval);
    tcg_temp_free_i32(lenval);

    QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_assert(TCGv reg, bool istrue) {
    QTRACE_INSTRUMENT_START();

    TCGv_i32 regidx = tcg_const_i32(GET_TCGV_I32(reg));
    TCGv_i32 istrueval = tcg_const_i32(istrue);

    gen_helper_qtrace_assert(regidx, istrueval);

    tcg_temp_free_i32(regidx);
    tcg_temp_free_i32(istrueval);

    QTRACE_INSTRUMENT_END();
}
