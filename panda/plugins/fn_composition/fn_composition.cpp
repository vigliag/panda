/**
* This plugin keeps tracks of function calls while executing a target process
* - it logs the readset and writeset of the first 5 calls to any function
* - it prints out the composition (count of arithmethic and total instruction)
*   for every encontered function
*
* Note: this is a standalone version of fn_memlogger, which should be preferred
* Note: the size of read/writes doesn't seem to be takne in consideration when
*       updating the readset/writeset
**/

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C

#include "panda/plugin.h" //include plugin api we are implementing
#include "panda/tcg-llvm.h"

//#include <llvm/PassManager.h>
#include <llvm/InstVisitor.h>
#include <llvm/IR/InstrTypes.h>
#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <map>
#include <set>
#include <unordered_set>
#include <unordered_map>

extern "C" {
#include <stdio.h>

bool init_plugin(void *);
void uninit_plugin(void *);
}

#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

using namespace std;

// A function is identified by its address
// (we care about a single process)
using fnid = target_ulong;

// Plugin argument: the process we are inspecting
target_ulong tracked_asid = 0;

// Stores last seen asid
target_ulong current_asid = 0;

// Stores a counters for the different kinds of instructions we care about
struct InstCount {
    uint32_t arit = 0;
    uint32_t tot = 0;
};

// Stores the InstCount for all seen functions
std::map<fnid, InstCount> totalCount;

// Stores the cached InstCount for every basic_block
// so that we avoid recomputing it again and again
std::map<target_ulong, InstCount> bb_count_cache;

// Tracks if LLVM translation is enabled. Initially false
bool llvm_enabled = false;

// LLVM instruction visitor which updates an internal InstCount
// on every seen instruction
class FnInstVisitor : public llvm::InstVisitor<FnInstVisitor> {
public:
    InstCount count;

    void visitBinaryOperator(llvm::BinaryOperator &I){
        count.arit++;
    }

    void visitInstruction(llvm::Instruction &I) {
        count.tot++;
    }
};

// Computes and caches the InstCount for a given BasicBlock
InstCount countAndAddToCache(TranslationBlock *tb){
    FnInstVisitor FIV;
    llvm::Function* bbfn = tb->llvm_function;
   
    if(bbfn){
        FIV.visit(*bbfn);
    } else {
        printf("no bbfn! \n");
    }

    target_ulong tb_identifier = tb->pc;
    bb_count_cache[tb_identifier] = FIV.count;
    return FIV.count;
}

// Invalidates the cache when translating/re-translating
int after_block_translate(CPUState *cpu, TranslationBlock *tb) {
    bb_count_cache.erase(tb->pc);
    return 0;
}

// Enables LLVM the first time we get to the process we want
// ASSUMING cr3 is changed inside of a block executing kernel code,
// then jumps inside of application code (which hasn't been translated yet,
// if this is the first time).
int asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {      
    current_asid = new_asid;

    if(current_asid == tracked_asid && !llvm_enabled){
        printf("enabling llvm\n");
        panda_enable_llvm();
        panda_enable_llvm_helpers();
        llvm_enabled = true;
    }

    return 0;
}

// Returns the current function identifier, asking the callstack_instr plugin
fnid getCurrentFunction(CPUState *cpu){
    target_ulong fns[1];
    int fns_returned = get_functions(fns,1,cpu);

    if(!fns_returned){
        printf("No fns returned\n");
        return 0;
    }
    return fns[0];
}

// Callback: Before executing a basic block:
// - we check if the cr3 is the right one
// - we take the currently executing function
// - we compute the instruction count of the block, and adds it to the function
int before_block_exec_cb(CPUState *cpu, TranslationBlock *tb){
    //CPUArchState *env = (CPUArchState*)cpu->env_ptr;

    // only go on if the asid is the one we are tracking
    if (panda_in_kernel(cpu) || tracked_asid != current_asid){
        return 0;
    }
    
    fnid current_fn = getCurrentFunction(cpu);
    target_ulong tb_identifier = tb->pc;
    
    // Count instructions in this basic block (or take from cache)
    InstCount bbcount; 
    if (bb_count_cache.count(tb_identifier)) {
        bbcount = bb_count_cache[tb_identifier];
    } else {
        bbcount = countAndAddToCache(tb);
    }

    totalCount[current_fn].arit += bbcount.arit;
    totalCount[current_fn].tot += bbcount.tot;

    return 0;
}

/* Writeset and readset tracking */
// We log the first 5 calls to any given function, together with their writeset,
// readset, etcetera

// Stores informations about a called function.
struct CallInfo {
    std::set<target_ulong> writeset;
    std::set<target_ulong> readset;
    target_ulong program_counter;
    uint64_t instruction_count_call;
    uint64_t instruction_count_ret;
};

// fnid -> number of times the function was called
std::unordered_map<uint64_t, int> calls;

// call_id -> CallInfo
std::unordered_map<uint64_t, CallInfo> call_infos; 

// On memory write callback
// - checks the cr3 is the right one
// - gets the instruction_count of the caller to use as identifier of this call
// - gets or create a CallInfo for this call (but only if this function has 
//   been called less than 5 times, else we return)
// - adds the write to the CallInfo's writeset
int mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    //CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    
    if (panda_in_kernel(cpu) || tracked_asid != current_asid){
        return 0;
    }

    CallstackStackEntry entry;
    int entries_n = get_call_entries(&entry, 1,cpu);
    if(entries_n == 0){
        cerr << "no callstack entries" << endl;
        return 0;
    }
    
    if( call_infos.count(entry.call_id)){
        // if we already have a CallInfo, we simply log this write
        call_infos[entry.call_id].writeset.insert(addr);

    } else if(calls[entry.function] < 5) {
        // we need to create a new CallInfo, then log this write
        calls[entry.function]++;
        call_infos[entry.call_id].program_counter = entry.function;
        call_infos[entry.call_id].writeset.insert(addr);

    } else {
        // we won't log any more calls
    }

    return 0;
}

// On memory read callback
// same logic as the write callback
// TODO size is not used
int mem_read_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size) {
    //CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    
    CallstackStackEntry entry;
    int entries_n = get_call_entries(&entry, 1,cpu);
    if(entries_n == 0){
        cerr << "no callstack entries" << endl;
        return 0;
    }
    
    if( call_infos.count(entry.call_id)){
        // if the call is already being logged, log this access
        call_infos[entry.call_id].readset.insert(addr);

    } else if(calls[entry.function] < 5) {
        // we still have calls to log, let's do that, then log this access
        calls[entry.function]++;
        call_infos[entry.call_id].program_counter = entry.function;
        call_infos[entry.call_id].readset.insert(addr);

    } else {
        // we won't log any more calls
    }
    
    return 0;
}

/* Plugin initialization */

void *plugin_self;
bool init_plugin(void *self) {
    plugin_self = self;
 
    panda_require("callstack_instr");
    if (!init_callstack_instr_api()) return false;
    
    panda_cb pcb;
    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
    pcb.before_block_exec = before_block_exec_cb;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    pcb.asid_changed = asid_changed;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
    pcb.virt_mem_after_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);
    pcb.virt_mem_before_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);
    
    //PPP_REG_CB("callstack_instr", on_call2, on_call);
    //PPP_REG_CB("callstack_instr", on_ret2, on_ret);

    panda_disable_tb_chaining();  //TODO actually needed?
    panda_enable_memcb();

    panda_arg_list *args = panda_get_args("fndetectcrypto");
    if (args != NULL) {
        tracked_asid = panda_parse_uint64_req(args, "asid", "asid to track");
    }

    printf("tracking asid " TARGET_FMT_ld  " \n", tracked_asid);

    return true;
}

// Helper function to represent a write/read sets as a compact string
std::string setToString(std::set<target_ulong> addrset){
    target_ulong base = 0;
    target_ulong consecutive = 0;
    std::stringstream ss;
    for (const auto& addr : addrset) {
        if(addr == base + consecutive + 1){
            consecutive++;
        } else {
            if(base){
                ss << reinterpret_cast<void*>(base) << "+" << consecutive << ";";
            }
            consecutive = 0;
            base = addr;
        }
    }
    if(base){
        ss << reinterpret_cast<void*>(base) << "+" << consecutive << ";";
    }
    return ss.str();
}

// Prints the collected stats on stdout
void printstats(){
    
    std::cout << "Logged calls: " << endl;
    for(auto const& callid_call : call_infos){
        auto& call = callid_call.second;
        std::cout << call.program_counter << " " << setToString(call.writeset) << " " << setToString(call.readset) << std::endl;
    }


    std::cout << "Stats (function_entrypoint, arit, arit/tot)" << std::endl;
    for (auto const& fn_count : totalCount){
        const InstCount& count = fn_count.second;
        std::cout << fn_count.first << " " << count.arit 
            << " " << (float)count.arit / count.tot << std::endl;
    }
}

void uninit_plugin(void *self) {
    printstats();
}
