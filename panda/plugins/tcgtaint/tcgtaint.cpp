/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */

// required qtrace_taint_instrumentation_enabled __STDC_FORMAT_MACROS

#include "tcgtaint.hpp"
#include "notify_taint.hpp"
#include "panda/plugin.h"
#include "tcg-taint/callbacks.h"
#include "tcg-taint/tcg-taint.h"
#include "logging.hpp"
#include <iostream>

TCGTaintContext tcgtaint_ctx;
bool taint_is_user_enabled = false;
bool taint_in_kernel_space = false;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

int tcgtaint_after_block_callback(CPUState *cpu, TranslationBlock *tb) {
    (void)tb;

    // Disable taint when switching to kernel space and viceversa
    //
    // NOTE(vigliag) this was originally in a callback fired on cpl change
    // hooking it to after_block_callback should hopefully work as well,
    // as, if I read correctly, cpl is changed in the sysenter executed as
    // part of the userspace tb

    // intentionally not flushing (not needed?)
    if (taint_is_user_enabled) {
        if (panda_in_kernel(cpu) && !taint_in_kernel_space) {
            qtrace_taint_instrumentation_enabled = false;
        } else {
            qtrace_taint_instrumentation_enabled = true;
        }
    }

    // TODO probably only needed when user manually enables/disables
    // panda_do_flush_tb();

    return 0;
}

int tcgtaint_loglevel;
extern int qemu_loglevel;

bool init_plugin(void *self) {
    // Init taint engine
    tcgtaint_ctx.taint_engine = new TaintEngine();

    // Hook into tgc taint instrumentation callbacks
    notify_taint_regalloc = qtrace::notify_taint_regalloc;
    notify_taint_moveM2R = qtrace::notify_taint_moveM2R;
    notify_taint_moveR2M = qtrace::notify_taint_moveR2M;
    notify_taint_moveR2R = qtrace::notify_taint_moveR2R;
    notify_taint_moveR2R_offset = qtrace::notify_taint_moveR2R_offset;
    notify_taint_combineR2R = qtrace::notify_taint_combineR2R;
    notify_taint_clearR = qtrace::notify_taint_clearR;
    notify_taint_clearM = qtrace::notify_taint_clearM;
    notify_taint_assert = qtrace::notify_taint_assert;
    notify_taint_endtb = qtrace::notify_taint_endtb;
    notify_taint_micro_ld = qtrace::notify_taint_micro_ld;
    notify_taint_micro_st = qtrace::notify_taint_micro_st;

    panda_arg_list *args = panda_get_args("tcgtaint");
    bool enable_taint_dereference = panda_parse_bool_opt(args, "taint_dereference", "taint through pointer deference (load only)");
    if(enable_taint_dereference){
        std::cout << "tcgtaint: taint_dereference " << enable_taint_dereference << std::endl;
    }
    tcgtaint_ctx.taint_engine->set_taint_dereference(enable_taint_dereference);

    tcgtaint_loglevel = panda_parse_uint32_opt(args, "loglevel", 1, "loglevel");
    if(tcgtaint_loglevel > MAX_LOG_LEVEL){
        std::cout << "warning, selected log level is above MAX_LOG_LEVEL" << std::endl;
    }
    tcg_taint_instrumentation_init();
    panda_disable_tb_chaining();
    panda_enable_precise_pc();

    // tcg_taint_instrumentation_enable();

    panda_cb pcb;
    pcb.after_block_exec = tcgtaint_after_block_callback;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

    // qemu_loglevel |= CPU_LOG_TB_IN_ASM | CPU_LOG_EXEC;

    return true;
}

void uninit_plugin(void *self) {
    delete tcgtaint_ctx.taint_engine;
    tcgtaint_ctx.taint_engine = nullptr;
    tcg_taint_instrumentation_disable();
}
