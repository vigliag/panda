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
#define __STDC_FORMAT_MACROS

#include <cstdio>
#include <cstdlib>
#include <cmath>

#include <map>
#include <unordered_map>
#include <set>
#include <vector>
#include <algorithm>
#include <iostream>

#include <capstone/capstone.h>
#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#elif defined(TARGET_PPC)
#include <capstone/ppc.h>
#endif

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "callstack_instr.h"

extern "C" {
#include "panda/plog.h"

#include "callstack_instr_int_fns.h"

bool translate_callback(CPUState* cpu, target_ulong pc);
int exec_callback(CPUState* cpu, target_ulong pc);
int before_block_exec(CPUState* cpu, TranslationBlock *tb);
int after_block_exec(CPUState* cpu, TranslationBlock *tb);
int after_block_translate(CPUState* cpu, TranslationBlock *tb);

bool init_plugin(void *);
void uninit_plugin(void *);

PPP_PROT_REG_CB(on_call);
PPP_PROT_REG_CB(on_ret);

PPP_PROT_REG_CB(on_call2);
PPP_PROT_REG_CB(on_ret2);
}

PPP_CB_BOILERPLATE(on_call);
PPP_CB_BOILERPLATE(on_ret);

PPP_CB_BOILERPLATE(on_call2);
PPP_CB_BOILERPLATE(on_ret2)


//Capstone handles
csh cs_handle_32;
csh cs_handle_64;


/* Data structures */

using instr_type = callstack_instr_type;
using stack_entry = CallstackStackEntry;

// pair of asid_identifier and thread_identifier
typedef std::pair<target_ulong,target_ulong> stackid;

// stackid -> shadow stack
std::map<stackid, std::vector<stack_entry>> callstacks;

// EIP -> instr_type
std::unordered_map<target_ulong, instr_type> call_cache;

/* Helpers */

static inline bool in_kernelspace(CPUArchState* env) {
#if defined(TARGET_I386)
    return ((env->hflags & HF_CPL_MASK) == 0);
#elif defined(TARGET_ARM)
    return ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC);
#else
    return false;
#endif
}

static inline target_ulong get_stack_pointer(CPUArchState* env) {
#if defined(TARGET_I386)
    return env->regs[R_ESP];
#elif defined(TARGET_ARM)
    return env->regs[13];
#else
    return 0;
#endif
}

// Strategies for obtaining a stack_identifier (runtime selectable)

enum StackidStrategy {
    ASID = 0,
    STACKPOINTER_HEURISTIC,
    THREAD_ID
};

// Default strategy is ASID, the others should be considered experimental
static StackidStrategy stackid_strategy = ASID;

/**
 * Gets the current thread identifier on 32bit windows NT systems
 * Only works in user-space, where the FS segment points to the TIB
 * @see https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
 */
uint32_t getThreadID(CPUState* cpu){
#ifdef TARGET_I386
    assert(!panda_in_kernel(cpu));

    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    uint32_t tib_address = env->segs[R_FS].base;
    uint32_t curr_thread_id_address = tib_address + 0x24;

    uint32_t curr_thread_id;
    panda_virtual_memory_read(cpu, curr_thread_id_address, (uint8_t*)(&curr_thread_id), 4);
    return curr_thread_id;
#else
    assert(false); //Not available on non-32bit TODO win64 support
#endif
}


/**
 * Obtains a stack_identifier by keeping track of seen stack_pointers
 * employs a static map <asid,set<stack_pointers>>
 */
static stackid get_stackid_from_closest_seen_stack(CPUState* cpu) {
    const target_ulong MAX_STACK_DIFF = 5000;

    // asid (process) -> set of seen stackpointers
    static std::map<target_ulong,std::set<target_ulong>> stacks_seen;

    // we cache the last seen stackpointer for the last seen process
    // the cache is invalidated when the process changes
    static target_ulong last_seen_sp = 0;
    static target_ulong last_seen_sp_asid = 0;

    CPUArchState* env = (CPUArchState*)cpu->env_ptr;

    // Get the current asid, asid=0 if in kernelspace
    target_ulong current_asid = in_kernelspace(env) ? 0 : panda_current_asid(cpu);
    // Get the stackpointer for the current processor
    target_ulong current_sp = get_stack_pointer(env);

    // If the last_seen_sp is still valid
    if (last_seen_sp && last_seen_sp_asid == current_asid) {

        // Try with the last_seen_sp first
        int64_t stack_diff = current_sp - last_seen_sp;
        if (std::abs(stack_diff) < MAX_STACK_DIFF) {
            return std::make_pair(current_asid, last_seen_sp);
        }

    } else {

        // mark the last_seen_sp as invalid
        last_seen_sp = 0;
    }

    auto &stackset = stacks_seen[current_asid];

    // If it's the first sp we've seen, insert it into the set, and return it
    if (stackset.empty()) {
        stackset.insert(current_sp);
        last_seen_sp = current_sp;
        last_seen_sp_asid = current_asid;
        return std::make_pair(current_asid,current_sp);
    }

    // Find the closest stack pointer we've seen
    target_ulong closest_known_sp = 0;
    auto lb = stackset.lower_bound(current_sp);

    if (lb != stackset.end()) {
        closest_known_sp = *lb;
    }

    if (lb != stackset.begin()) {
        lb--;
        target_ulong value_less_than = *lb;
        const int64_t diff_value_lt = value_less_than - current_sp;
        const int64_t diff_sp_closest_sp = closest_known_sp - current_sp;
        if( !closest_known_sp || std::abs(diff_value_lt) < std::abs(diff_sp_closest_sp) ){
            closest_known_sp = current_sp;
        }
    }

    // Is the closest_known_sp close enough?
    const int64_t sp_diff = current_sp - closest_known_sp;
    uint32_t diff = static_cast<uint32_t>(std::abs(sp_diff));
    if (diff < MAX_STACK_DIFF) {
        last_seen_sp = current_sp;
        last_seen_sp_asid = current_asid;
        return std::make_pair(current_asid, closest_known_sp);
    }

    // If it's not close enough, then classify it as a new stack,
    // store it, then and return it
    stackset.insert(current_sp);
    last_seen_sp = current_sp;
    last_seen_sp_asid = current_asid;
    return std::make_pair(current_asid, current_sp);
}

static stackid get_stackid(CPUState* cpu) {
    switch(stackid_strategy){
    case ASID:
        return std::make_pair(panda_current_asid(cpu),0);
    case STACKPOINTER_HEURISTIC:
        return get_stackid_from_closest_seen_stack(cpu);
    case THREAD_ID:
        if(panda_in_kernel(cpu)){
            return std::make_pair(panda_current_asid(cpu), 0);
        } else {
            return std::make_pair(panda_current_asid(cpu), getThreadID(cpu));
        }
    default:
        assert(0);
    }
}

/**
 * Disassembles a block of code, then returns the instr_type of the last
 * instruction (CALL, RET, or UNKNOWN)
*/
static instr_type disas_block(CPUArchState* env, target_ulong pc, uint32_t size) {

    CPUState *cpu = ENV_GET_CPU(env);

    unsigned char *buf = (unsigned char *) malloc(size);
    int err = panda_virtual_memory_rw(cpu, pc, buf, size, 0);
    if (err == -1) printf("Couldn't read TB memory!\n");
    instr_type res = INSTR_UNKNOWN;

#if defined(TARGET_I386)
    csh handle = (env->hflags & HF_LMA_MASK) ? cs_handle_64 : cs_handle_32;
#elif defined(TARGET_ARM)
    csh handle = cs_handle_32;

    if (env->thumb){
        cs_option(handle, CS_OPT_MODE, CS_MODE_THUMB);
    }
    else {
        cs_option(handle, CS_OPT_MODE, CS_MODE_ARM);
    }

#elif defined(TARGET_PPC)
    csh handle = cs_handle_32;
#endif

    cs_insn *insn;
    cs_insn *end;
    size_t count = cs_disasm(handle, buf, size, pc, 0, &insn);
    if (count <= 0) goto done2;

    for (end = insn + count - 1; end >= insn; end--) {
        if (!cs_insn_group(handle, end, CS_GRP_INVALID)) {
            break;
        }
    }
    if (end < insn) goto done;

    if (cs_insn_group(handle, end, CS_GRP_CALL)) {
        res = INSTR_CALL;
    } else if (cs_insn_group(handle, end, CS_GRP_RET)) {
        res = INSTR_RET;
    } else {
        res = INSTR_UNKNOWN;
    }

done:
    cs_free(insn, count);
done2:
    free(buf);
    return res;
}

// Every time a block is translated, save in call_cache the kind of instruction
// it ends with
int after_block_translate(CPUState *cpu, TranslationBlock *tb) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    call_cache[tb->pc] = disas_block(env, tb->pc, tb->size);

    return 1;
}

// Before a block is executed, check if program-counter we are jumping in
// is a registerd return address, if it is, then we are returning, and we can remove our
// stackframe from our shadow stack
int before_block_exec(CPUState *cpu, TranslationBlock *tb) {
    stackid current_stackid = get_stackid(cpu);
    target_ulong pc = tb->pc;

    // TODO should check if the last executed instruction is indeed a return?

    std::vector<stack_entry> &v = callstacks[current_stackid];
    if (v.empty()) return 1;

    // search the shadow stack top-to-bottom order, for a max depth of 30

    const int max_depth = 30;
    bool found = false;

    auto stack_it = v.rbegin();
    unsigned depth = 0;
    for(; stack_it != v.rend() && depth < max_depth; stack_it++, depth++){
        if(stack_it->return_address == pc) {found = true; break;}
    }

    if(!found){
        // Not a return!
        return 0;
    }

    PPP_RUN_CB(on_ret2, cpu, stack_it->function, stack_it->call_id, depth);
    PPP_RUN_CB(on_ret, cpu, stack_it->function);

    // remove stack frames in between from the shadow stack

    //obtain forward iterator
    std::advance(stack_it, 1);
    auto found_element_it = stack_it.base();

    //for(auto it = found_element_it; it != v.end(); it++){
        // call on_discarded function
    //}

    v.erase(found_element_it, v.end());

    return 0;
}

// After a block executes, we check if its last instruction was a CALL
// if it is, then we add a new frame to our shadow stack
int after_block_exec(CPUState* cpu, TranslationBlock *tb) {
    static int justEnabled = 1;
    if(justEnabled){
        justEnabled = 0;
        return 1;
    }

    assert(tb);
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    instr_type tb_type = call_cache.at(tb->pc);

    if (tb_type == INSTR_CALL) {

        // This retrieves the pc in an architecture-neutral way
        // The program counter, updated by the call, is the address of the
        // called function
        target_ulong pc, cs_base;
        uint32_t flags;
        cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);

        stackid current_stackid = get_stackid(cpu);

        stack_entry se;
        se.function = pc; //the program counter has been updated and it is at the beginning of the called function
        se.return_address = tb->pc + tb->size; //the call instruction is the last of its basic block
        se.kind = tb_type;
        se.call_id = rr_get_guest_instr_count();
        se.called_by = callstacks[current_stackid].empty() ? 
            0 : callstacks[current_stackid].back().call_id;

        callstacks[current_stackid].push_back(se);

        PPP_RUN_CB(on_call2, cpu, pc, se.call_id);
        PPP_RUN_CB(on_call, cpu, pc);
    }
    else if (tb_type == INSTR_RET) {
        //printf("Just executed a RET in TB " TARGET_FMT_lx "\n", tb->pc);
        //if (next) printf("Next TB: " TARGET_FMT_lx "\n", next->pc);
    }

    return 1;
}

uint64_t get_current_callid(CPUState* cpu){
    std::vector<stack_entry> &v = callstacks[get_stackid(cpu)];
    if (v.empty()) return 0;
    return v.back().call_id;
}

// Public interface implementation
int get_callers(target_ulong callers[], int n, CPUState* cpu) {
    std::vector<stack_entry> &v = callstacks[get_stackid(cpu)];
    auto rit = v.rbegin();
    int i = 0;
    for (/*no init*/; rit != v.rend() && i < n; ++rit, ++i) {
        callers[i] = rit->return_address;
    }
    return i;
}

/**
 * @brief get_call_entries gets you the topmost n entries from the shadow stack
 *   (current asid and thread, if possible) in reversed order (topmost first)
 * @param entries, out array of entries with at least n positions
 * @param n, max number of entries to return
 * @param cpu, cpu
 * @return the number of entries written
 */
int get_call_entries(struct CallstackStackEntry entries[], int n, CPUState *cpu){
    std::vector<stack_entry> &v = callstacks[get_stackid(cpu)];
    auto rit = v.rbegin(); //reverse iterator
    int i = 0;
    for (/*no init*/; rit != v.rend() && i < n; ++rit, ++i) {
        entries[i] = *rit;
    }
    return i;
}

#define CALLSTACK_MAX_SIZE 16
// writes an entry to the pandalog with callstack info (and instr count and pc)
Panda__CallStack *pandalog_callstack_create() {
    assert (pandalog);
    CPUState *cpu = first_cpu;
    uint32_t n = 0;
    std::vector<stack_entry> &v = callstacks[get_stackid(cpu)];
    auto rit = v.rbegin();
    for (/*no init*/; rit != v.rend() && n < CALLSTACK_MAX_SIZE; ++rit) {
        n ++;
    }
    Panda__CallStack *cs = (Panda__CallStack *) malloc (sizeof(Panda__CallStack));
    *cs = PANDA__CALL_STACK__INIT;
    cs->n_addr = n;
    cs->addr = (uint64_t *) malloc (sizeof(uint64_t) * n);
    v = callstacks[get_stackid(cpu)];
    rit = v.rbegin();
    uint32_t i=0;
    for (/*no init*/; rit != v.rend() && n < CALLSTACK_MAX_SIZE; ++rit, ++i) {
        cs->addr[i] = rit->return_address;
    }
    return cs;
}


void pandalog_callstack_free(Panda__CallStack *cs) {
    free(cs->addr);
    free(cs);
}


int get_functions(target_ulong functions[], int n, CPUState* cpu) {
    auto &v = callstacks[get_stackid(cpu)];
    if (v.empty()) {
        return 0;
    }
    auto rit = v.rbegin();
    int i = 0;
    for (/*no init*/; rit != v.rend() && i < n; ++rit, ++i) {
        functions[i] = rit->function;
    }
    return i;
}

void get_prog_point(CPUState* cpu, prog_point *p) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    if (!p) return;

    // Get address space identifier
    target_ulong asid = panda_current_asid(ENV_GET_CPU(env));

    // Lump all kernel-mode CR3s together

    if(!in_kernelspace(env)){
        p->cr3 = asid;
    } else {
        p->cr3 = 0;
    }

    // Try to get the caller
    int n_callers = 0;
    n_callers = get_callers(&p->caller, 1, cpu);

    if (n_callers == 0) {
#ifdef TARGET_I386
        // fall back to EBP on x86
        int word_size = (env->hflags & HF_LMA_MASK) ? 8 : 4;
        panda_virtual_memory_rw(cpu, env->regs[R_EBP]+word_size, (uint8_t *)&p->caller, word_size, 0);
#endif
#ifdef TARGET_ARM
        p->caller = env->regs[14]; // LR
#endif

    }

    p->pc = cpu->panda_guest_pc;
}



bool init_plugin(void *self) {
#if defined(TARGET_I386)
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
#if defined(TARGET_X86_64)
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle_64) != CS_ERR_OK)
#endif
#elif defined(TARGET_ARM)
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cs_handle_32) != CS_ERR_OK)
#elif defined(TARGET_PPC)
    if (cs_open(CS_ARCH_PPC, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
#endif
        return false;

    // Need details in capstone to have instruction groupings
    cs_option(cs_handle_32, CS_OPT_DETAIL, CS_OPT_ON);
#if defined(TARGET_X86_64)
    cs_option(cs_handle_64, CS_OPT_DETAIL, CS_OPT_ON);
#endif

    panda_cb pcb;

    panda_enable_memcb();
    panda_enable_precise_pc();

    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
    pcb.after_block_exec = after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    panda_arg_list *args = panda_get_args("callstack_instr");

    const char *stackid_strategy_str = panda_parse_string_opt(args, "stackid_strategy", nullptr, "strategy to employ in obtaining a stack identifier (thread_id, heuristic, asid)");
    if (stackid_strategy_str == nullptr) {
        if(panda_os_type == OST_WINDOWS && 0 == strcmp(panda_os_details, "7")){
            stackid_strategy = StackidStrategy::THREAD_ID;
        } else {
            stackid_strategy = StackidStrategy::ASID;
        }
    } else if (0 == strcmp(stackid_strategy_str, "thread_id")) {
        stackid_strategy = StackidStrategy::THREAD_ID;
    } else if (0 == strcmp(stackid_strategy_str, "heuristic")) {
        stackid_strategy = StackidStrategy::STACKPOINTER_HEURISTIC;
    } else if (0 == strcmp(stackid_strategy_str, "asid")){
        stackid_strategy = StackidStrategy::ASID;
    } else {
        std::cerr << "unrecognized option " << stackid_strategy_str << std::endl;
        return false;
    }

    switch (stackid_strategy) {
    case StackidStrategy::THREAD_ID:
        std::cout << "callstack_instr employing thread_id strategy" << std::endl;
        break;
    case StackidStrategy::ASID:
        std::cout << "callstack_instr employing asid strategy" << std::endl;
        break;
    case StackidStrategy::STACKPOINTER_HEURISTIC:
        std::cout << "callstack_instr employing stackpointer_heuristic strategy" << std::endl;
        break;
    }

    return true;
}

void uninit_plugin(void *self) {
}
