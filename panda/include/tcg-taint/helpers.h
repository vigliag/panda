//included from target/i386/helper.h
DEF_HELPER_3(qtrace_reg2mem, void, tl, tl, i32)
DEF_HELPER_3(qtrace_mem2reg, void, tl, tl, i32)
DEF_HELPER_2(qtrace_mov, void, tl, tl)
DEF_HELPER_1(qtrace_clearR, void, tl)
DEF_HELPER_0(qtrace_endtb, void)
DEF_HELPER_2(qtrace_combine2, void, tl, tl)
DEF_HELPER_3(qtrace_combine3, void, tl, tl ,tl)
DEF_HELPER_5(qtrace_deposit, void, tl, tl, tl, i32, i32)
DEF_HELPER_2(qtrace_assert, void, tl, tl)
DEF_HELPER_3(qtrace_micro_st, void, tl, tl, i32)
DEF_HELPER_3(qtrace_micro_ld, void, tl, tl, i32)