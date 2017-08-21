// This plugin logs the first N calls to any given function of a given asid.
// Then extracts synthetic informations about the buffers each function uses

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "panda/plugin.h" //include plugin api we are implementing
#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <map>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <vector>


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
#include <stdio.h>
    
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
}

#include "EntropyCalculator.hpp"

using namespace std;

// A function is identified by its address
// (we care about a single process)
using fnid = target_ulong;


/* Data structures */

// The process whose execution we want to inspect
target_ulong tracked_asid = 0;

// Stores informations about a called function.
struct CallInfo {
    std::map<target_ulong, uint8_t> writeset;
    std::map<target_ulong, uint8_t> readset;
    target_ulong program_counter;
    uint64_t instruction_count_call;
    uint64_t instruction_count_ret;
    uint64_t called_by = 0; //TODO
};

// fnid -> number of calls
std::unordered_map<uint64_t, int> calls;

// call_id -> CallInfo
std::unordered_map<uint64_t, CallInfo> call_infos; 

// Gets the current stack entry from callstack_instr
CallstackStackEntry getCurrentEntry(CPUState *cpu){
    CallstackStackEntry entry;
    int entries_n = get_call_entries(&entry, 1,cpu);
    assert(entries_n);
    return entry;
}

/* Memory access logging */


/** When a call instruciton is detected, create a new CallInfo */
void on_call(CPUState *cpu, target_ulong entrypoint, uint64_t callid){
    if (panda_in_kernel(cpu) || tracked_asid != panda_current_asid(cpu)){
        return;
    }

    CallstackStackEntry current_entry = getCurrentEntry(cpu);

    if(calls[entrypoint] < 5) {
        // create a call_info for this call, successive memory callbacks 
        // will populate its writeset and readset
        calls[entrypoint]++;
        call_infos[callid].program_counter = entrypoint;
        call_infos[callid].called_by = current_entry.call_id;
    }
}


/** On write, add to the writeset (if CallInfo exists) */
int mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    //CPUArchState *env = (CPUArchState*)cpu->env_ptr;

    uint8_t *data = static_cast<uint8_t*>(buf);
    if (panda_in_kernel(cpu) || tracked_asid != panda_current_asid(cpu)){
        return 0;
    }

    CallstackStackEntry entry = getCurrentEntry(cpu);
    
    if( call_infos.count(entry.call_id)){
        for(target_ulong i=0; i < size; i++){
            call_infos[entry.call_id].writeset[addr +i] = data[i];
        }
    }

    return 0;
}


/** On read, add to the readset (if CallInfo exists) */
int mem_read_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    //CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    uint8_t *data = static_cast<uint8_t*>(buf);

    if (panda_in_kernel(cpu) || tracked_asid != panda_current_asid(cpu)){
        return 0;
    }

    CallstackStackEntry entry = getCurrentEntry(cpu);
    
    if( call_infos.count(entry.call_id)){
 
        for(target_ulong i=0; i < size; i++){

            //if this address hasn't been previously written by the current
            //function, then add it to the readset
            if(!call_infos[entry.call_id].writeset.count(addr + i)){
                call_infos[entry.call_id].readset[addr +i] = data[i];
            }
        }
    }
    
    return 0;
}


/* Data access processing */

/* Holds a synthetic description of a given buffer */
struct bufferinfo {
    target_ulong base = 0;
    target_ulong len = 0;
    float entropy = -1;

    std::string toString() const {
        std::stringstream ss;
        ss << reinterpret_cast<void*>(base) << "+" << len << ":" << entropy << ";";
        return ss.str();
    }
};

/* Computes a vector of BufferInfo from a map<address,data> (read/writeset) */
std::vector<bufferinfo> toBufferInfos(std::map<target_ulong, uint8_t> addrset){
    std::vector<bufferinfo> res;
    bufferinfo temp;
    EntropyCalculator ec;

    for (const auto& addr_data : addrset) {
        const auto& addr = addr_data.first;

        if(addr == temp.base + temp.len + 1){
            // continue previous buffer
            temp.len++;
            ec.add(addr_data.second);

        } else {
            // start new buffer

            if(temp.base){
                // save the old one first
                temp.entropy = ec.get();
                res.push_back(temp);
            }

            // init new buffer
            temp.len = 0;
            temp.base = addr;
            ec.reset();
            ec.add(addr_data.second);
        }
    }

    // process last buffer (if any - ie addrset wasn't empty)
    if(temp.base){
        temp.entropy = ec.get();
        res.push_back(temp);
    }

    return res;
}

/** On return, if the CallInfo exists, log it to stdout, then erase it */
void on_ret(CPUState *cpu, target_ulong entrypoint, uint64_t callid, uint32_t skipped_frames){
    if (panda_in_kernel(cpu) || tracked_asid != panda_current_asid(cpu)){
        return;
    }

    if(call_infos.count(callid) == 0){
        // we haven't logged this call, probably because it's been called more 
        // than N times
        return;
    }
    
    auto& call = call_infos[callid];

    if(skipped_frames){
        std::cerr << "Warning, skipped frames: " << skipped_frames << std::endl;
    }

    std::vector<bufferinfo> writebuffs = toBufferInfos(call.writeset);
    std::vector<bufferinfo> readbuffs = toBufferInfos(call.readset);

    std::cout << "RET " << call.program_counter << " writes=";
    for(const bufferinfo& wrb : writebuffs){
        std::cout << wrb.toString();
    }
    std::cout << " reads=";
    for(const bufferinfo& rdb : readbuffs){
        std::cout << rdb.toString();
    }
    std::cout << " called_by=" << call.called_by << std::endl;

    call_infos.erase(callid);
}


/* Plugin initialization */

void *plugin_self;
bool init_plugin(void *self) {
    plugin_self = self;
 
    panda_require("callstack_instr");
    if (!init_callstack_instr_api()) return false;
    
    panda_cb pcb;
    
    //pcb.asid_changed = asid_changed;
    //panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    pcb.virt_mem_after_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);
    pcb.virt_mem_after_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);
    
    PPP_REG_CB("callstack_instr", on_call2, on_call);
    PPP_REG_CB("callstack_instr", on_ret2, on_ret);

    panda_disable_tb_chaining();  //TODO actually needed?
    panda_enable_memcb();

    panda_arg_list *args = panda_get_args("fn_memlogger");
    if (args != NULL) {
        tracked_asid = panda_parse_uint64_req(args, "asid", "asid to track");
    }

    printf("tracking asid " TARGET_FMT_ld  " \n", tracked_asid);

    return true;
}


/** Logs to the standard out the calls that haven't returned */
void printstats(){
    std::cerr << "Missed calls: " << std::endl;
    for(auto const& callid_call : call_infos){
        auto& call = callid_call.second;
        std::cerr << call.program_counter << " at " << callid_call.first << std::endl;
    }

}

void uninit_plugin(void *self) {
    printstats();
}
