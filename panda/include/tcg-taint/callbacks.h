#pragma once

/* Allocation of CPU registers */
typedef void (*notify_taint_regalloc_t)(target_ulong reg, const char *name);
extern notify_taint_regalloc_t notify_taint_regalloc;

/* Data movement */

typedef void (*notify_taint_moveM2R_t)(target_ulong addr, int size, bool istmp, target_ulong reg);
extern notify_taint_moveM2R_t notify_taint_moveM2R;

typedef void (*notify_taint_moveR2M_t)(bool istmp, target_ulong reg, target_ulong addr, int size);
extern notify_taint_moveR2M_t notify_taint_moveR2M;

typedef void (*notify_taint_moveR2R_t)(bool srctmp, target_ulong src, bool dsttmp, target_ulong dst);
extern notify_taint_moveR2R_t notify_taint_moveR2R;

/* Move a source (sub)register into destination (sub)register */
typedef void (*notify_taint_moveR2R_offset_t)(bool srctmp, target_ulong src,
                                    unsigned int srcoff,
                                    bool dsttmp, target_ulong dst,
                                    unsigned int dstoff,
                                    int size);
extern notify_taint_moveR2R_offset_t notify_taint_moveR2R_offset;                          

/* Data combination */
typedef void (*notify_taint_combineR2R_t)(bool srctmp, target_ulong src,
                                bool dsttmp, target_ulong dst);
extern notify_taint_combineR2R_t notify_taint_combineR2R;

/* Clear taint status */
typedef void (*notify_taint_clearR_t)(bool istmp, target_ulong reg);
extern notify_taint_clearR_t notify_taint_clearR;

typedef void (*notify_taint_clearM_t)(target_ulong addr, int size);
extern notify_taint_clearM_t notify_taint_clearM;

/* Assertions on registry taintedness, just for debugging */
typedef void (*notify_taint_assert_t)(target_ulong reg, bool istrue);
extern notify_taint_assert_t notify_taint_assert;

/* Notify a CPL switch */
//typedef void (*notify_taint_cpl_t)(target_ulong cr3, target_ulong newcpl);
//extern notify_taint_cpl_t notify_taint_cpl;

/* Switch and query taint-tracker state */
//typedef void (*notify_taint_set_state_t)(bool state);
//extern notify_taint_set_state_t notify_taint_set_state;

//bool notify_taint_get_state(void);

/* End of translation block */
//TODO use panda equivalent
typedef void (*notify_taint_endtb_t)(void);
extern notify_taint_endtb_t notify_taint_endtb;

/* Set taint label */
//typedef void (*notify_taint_memory_t)(target_ulong addr, unsigned int size, int label);
//extern notify_taint_memory_t notify_taint_memory;

//typedef void (*notify_taint_register_t)(bool istmp, unsigned char regno, int label);
//extern notify_taint_register_t notify_taint_register;

/* Check taint status */
//bool notify_taint_check_memory(target_ulong addr, unsigned int size);
