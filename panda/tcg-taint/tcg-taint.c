#include "panda/plugin.h"
#include "tcg-taint/tcg-taint.h"
#include "tcg-taint/callbacks.h"
#include "assert.h"

bool qtrace_taint_instrumentation_enabled = false;
bool qtrace_in_instrumentation = false;

notify_taint_regalloc_t notify_taint_regalloc = 0;
notify_taint_moveM2R_t notify_taint_moveM2R  = 0;
notify_taint_moveR2M_t notify_taint_moveR2M = 0;
notify_taint_moveR2R_t notify_taint_moveR2R = 0;
notify_taint_moveR2R_offset_t notify_taint_moveR2R_offset = 0;
notify_taint_combineR2R_t notify_taint_combineR2R = 0;
notify_taint_clearR_t notify_taint_clearR = 0;
notify_taint_clearM_t notify_taint_clearM = 0;
notify_taint_assert_t notify_taint_assert = 0;
notify_taint_endtb_t notify_taint_endtb = 0;

static void tgc_taint_intstrumentation_check_callbacks(void){
    assert(notify_taint_regalloc);
    assert(notify_taint_moveM2R);
    assert(notify_taint_moveR2M);
    assert(notify_taint_moveR2R);
    assert(notify_taint_moveR2R_offset);
    assert(notify_taint_combineR2R);
    assert(notify_taint_clearR);
    assert(notify_taint_clearM);
    assert(notify_taint_assert);
    assert(notify_taint_endtb);
}

void tcg_taint_instrumentation_init(void){
    tgc_taint_intstrumentation_check_callbacks();
}


void tcg_taint_instrumentation_enable(void){
    qtrace_taint_instrumentation_enabled = true;
    panda_do_flush_tb();
}

void tcg_taint_instrumentation_disable(void){
    qtrace_taint_instrumentation_enabled = false;
    panda_do_flush_tb();
}
