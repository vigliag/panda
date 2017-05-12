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

#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
}

using namespace std;
using fnid = target_ulong;

target_ulong tracked_asid = 0;
target_ulong current_asid = 0;

//NOTE we'll assume a BB is contained into a function
//TODO should I handle BB invalidation?

struct InstCount {
    uint32_t arit = 0;
    uint32_t tot = 0;
};

std::map<fnid, InstCount> totalCount;
std::map<target_ulong, InstCount> bb_count_cache;
bool llvm_enabled = false;

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

// invalidate cache when translating/re-translating
int after_block_translate(CPUState *cpu, TranslationBlock *tb) {
    bb_count_cache.erase(tb->pc);
    return 0;
}

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

fnid getCurrentFunction(CPUState *cpu){
    target_ulong fns[1];
    int fns_returned = get_functions(fns,1,cpu);
    if(!fns_returned){
        printf("No fns returned\n");
        return 0;
    }
    return fns[0];
}

// Before executing a basic block, check if the cr3 is the right one, if it is,
// take current executing function, and assign it the instruction count of the block
// ASSUMING calls are executed in the previous block
int before_block_exec_cb(CPUState *cpu, TranslationBlock *tb){
    //CPUArchState *env = (CPUArchState*)cpu->env_ptr;

    // only go on if the asid is the one we are tracking
    if (panda_in_kernel(cpu) || tracked_asid != current_asid){
        return 0;
    }
    
    fnid current_fn = getCurrentFunction(cpu);
    target_ulong tb_identifier = tb->pc;
    
    // Count instructions in this basic block 
    // (take from cache if already counted)
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

struct CallInfo {
    std::set<target_ulong> writeset;
    std::set<target_ulong> readset;
    target_ulong program_counter;
    uint64_t instruction_count_call;
    uint64_t instruction_count_ret;
};

//fnid -> number of calls
std::unordered_map<uint64_t, int> calls;

//call_id -> CallInfo
std::unordered_map<uint64_t, CallInfo> call_infos; 

int mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    //CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    
    if (panda_in_kernel(cpu) || tracked_asid != current_asid){
        return 0;
    }

    callstack_stack_entry entry;
    int entries_n = get_call_entries(&entry, 1,cpu);
    assert(entries_n);
    
    if( call_infos.count(entry.call_id)){
        // if the call is already being logged, log this write
        call_infos[entry.call_id].writeset.insert(addr);

    } else if(calls[entry.function] < 5) {
        // we still have calls to log, let's do that, then log this write
        calls[entry.function]++;
        call_infos[entry.call_id].program_counter = entry.function;
        call_infos[entry.call_id].writeset.insert(addr);

    } else {
        // we won't log any more calls
    }

    return 0;
}


int mem_read_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size) {
    //CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    
    callstack_stack_entry entry;
    int entries_n = get_call_entries(&entry, 1,cpu);
    assert(entries_n);
    
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
