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

void countAndAddToCache(TranslationBlock *tb){
    FnInstVisitor FIV;
    llvm::Function* bbfn = (llvm::Function*) tb->llvm_tc_ptr;
   
    if(bbfn){
        FIV.visit(*bbfn);
    } else {
        printf("no bbfn! \n");
    }

    target_ulong tb_identifier = tb->pc;
    bb_count_cache[tb_identifier] = FIV.count;
}

int after_block_translate(CPUState *cpu, TranslationBlock *tb) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;

    if (panda_in_kernel(cpu) ||
         tracked_asid != panda_current_asid(ENV_GET_CPU(env))){
        return 0;
    }
    
    if(!llvm_enabled){
        printf("enabling llvm\n");
        panda_enable_llvm();
        panda_enable_llvm_helpers();
        llvm_enabled = true;
    }

    countAndAddToCache(tb);

    return 0;
}

int before_block_exec_cb(CPUState *cpu, TranslationBlock *tb){
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;

    // only go on if the asid is the one we are tracking
    if (panda_in_kernel(cpu) ||
         tracked_asid != panda_current_asid(ENV_GET_CPU(env))){
        return 0;
    }
    
    // get the current function identifier
    target_ulong fns[1];
    int fns_returned = get_functions(fns,1,cpu);
    if(!fns_returned){
        printf("No fns returned\n");
        return 0;
    }
    fnid current_fn = fns[0];

    // get the identifier of this basic block
    target_ulong tb_identifier = tb->pc;
    
    if (bb_count_cache.count(tb_identifier)) {
        InstCount& bbcount = bb_count_cache[tb_identifier];
        
        totalCount[current_fn].arit += bbcount.arit;
        totalCount[current_fn].tot += bbcount.tot;
    } else {
        printf("bb " TARGET_FMT_ld " not found in cache, this shouldn't happen \n", tb->pc);
    }

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

    panda_arg_list *args = panda_get_args("fndetectcrypto");
    if (args != NULL) {
        tracked_asid = panda_parse_uint64_req(args, "asid", "asid to track");
    }

    printf("tracking asid " TARGET_FMT_ld  " \n", tracked_asid);

    printf("enabling llvm\n");
    panda_enable_llvm();
    panda_enable_llvm_helpers();
    llvm_enabled = true;

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
