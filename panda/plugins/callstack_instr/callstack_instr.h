#ifndef __CALLSTACK_INSTR_H
#define __CALLSTACK_INSTR_H

#include "prog_point.h"

enum callstack_instr_type {
  INSTR_UNKNOWN = 0,
  INSTR_CALL,
  INSTR_RET,
  INSTR_SYSCALL,
  INSTR_SYSRET,
  INSTR_SYSENTER,
  INSTR_SYSEXIT,
  INSTR_INT,
  INSTR_IRET,
};

struct CallstackStackEntry {
    target_ulong function; //function entrypoint
    target_ulong return_address;  //return address
    callstack_instr_type kind;  //way the function has been called
    uint64_t call_id; //unique identifier for this function call (will be set to the instruction count)
    uint64_t called_by; //callid of the calling function
};

typedef void (* on_call_t)(CPUState *env, target_ulong func);
typedef void (* on_ret_t)(CPUState *env, target_ulong func);

typedef void (* on_call2_t)(CPUState *env, target_ulong entrypoint, uint64_t callid);
typedef void (* on_ret2_t)(CPUState *env, target_ulong entrypoint, uint64_t callid, uint32_t skipped_frames);
typedef void (* on_forcedret_t)(CPUState *env, target_ulong entrypoint, uint64_t callid, uint32_t skipped_frames);
#endif
