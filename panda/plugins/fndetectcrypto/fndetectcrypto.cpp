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
    if (panda_in_kernel(cpu) ||
        tracked_asid != current_asid){
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

    //TODO actually needed?
    panda_disable_tb_chaining();

    panda_arg_list *args = panda_get_args("fndetectcrypto");
    if (args != NULL) {
        tracked_asid = panda_parse_uint64_req(args, "asid", "asid to track");
    }

    printf("tracking asid " TARGET_FMT_ld  " \n", tracked_asid);

    return true;
}


void printstats(){
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
