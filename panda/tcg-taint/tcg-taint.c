#include "tcg-taint.h"
#include "callbacks.h"

bool qtrace_taint_enabled = false;
bool qtrace_instrument = false;

notify_taint_regalloc_t notify_taint_regalloc = nullptr;
notify_taint_moveM2R_t notify_taint_moveM2R  = nullptr;
notify_taint_moveR2M_t notify_taint_moveR2M = nullptr;
notify_taint_moveR2R_t notify_taint_moveR2R = nullptr;
notify_taint_moveR2R_offset_t notify_taint_moveR2R_offset = nullptr;
notify_taint_combineR2R_t notify_taint_combineR2R = nullptr;
notify_taint_clearR_t notify_taint_clearR = nullptr;
notify_taint_clearM_t notify_taint_clearM = nullptr;
notify_taint_assert_t notify_taint_assert = nullptr;

void tcg_taint_enable(void){
    assert(notify_taint_regalloc);
    assert(notify_taint_moveM2R);
    assert(notify_taint_moveR2M);
    assert(notify_taint_moveR2R);
    assert(notify_taint_moveR2R_offset);
    assert(notify_taint_combineR2R);
    assert(notify_taint_clearR);
    assert(notify_taint_clearM);
    assert(notify_taint_assert);

    qtrace_taint_enabled = true;
}