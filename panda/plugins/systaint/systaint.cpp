#include "panda/plugin.h" //include plugin api we are implementing
#include "taint2/taint2.h" //include taint2 module we'll use
#include "callstack_instr/callstack_instr.h"
#include "sysevent/sysevent.h"
#include "syscall_listener.hpp"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C

extern "C" {

#include "taint2/taint2_ext.h"
#include "callstack_instr/callstack_instr_ext.h"
#include "panda/plog.h"

bool init_plugin(void *);
void uninit_plugin(void *);
int guest_hypercall_callback(CPUState *cpu);
}

#include <iostream>
#include <sstream>
#include <string>

#include <map>
#include <set>
#include <unordered_set>
#include <stdio.h>
#include <cstdint>

using namespace std;

#include "callmemaccesstracker.hpp"
#include "logging.hpp"

// Dependency tree we are going to build
using dependencySet = std::unordered_set<uint32_t>;
static std::map<uint32_t, dependencySet> eventDependencies;


#ifdef TARGET_I386

uint32_t current_syscall = 0;
uint32_t tracked_asid = 0;

static uint32_t current_event = 0;
static uint32_t tracked_encoding_fn = 0;
static bool no_llvm = false;
static const char* outfile = nullptr;
static FILE* outfp = nullptr;
CallMemAccessTracker current_event_memtracker;

/* On windows, checks if a virtual address is in user-space */
bool isUserSpaceAddress(uint64_t virt_addr){
    const uint64_t MMUserProbeAddress = 0x7fff0000; // Start of kernel memory
    return virt_addr < MMUserProbeAddress;
}

/* Used as a callback to add new_label as a dependency to this_label
   uses global data structures */
int currentEventDependencyAdder(uint32_t dependency, void *address){
    target_ulong addr = *(target_ulong*) address;

    if(dependency == current_event){
        return 0;
    }

    if (eventDependencies[current_event].count(dependency) == 0){
        printf("adding dependency %u -> %u \n", dependency, current_event);
        eventDependencies[current_event].insert(dependency);
    }

    current_event_memtracker.readdep(addr, dependency);
    return 0;
}

using taint2_iter_callback = int (*)(uint32_t, void*);

int readLabels(CPUState* cpu, target_ulong addr, target_ulong size, taint2_iter_callback callback){
    if(!taint2_enabled()) return 0;

    uint64_t abs_addr = panda_virt_to_phys(cpu, addr);
    if(abs_addr == static_cast<uint64_t>(-1)){
        cerr << "panda_virt_to_phys " << addr << " errored" << endl;
        return 0;
    }

    for(uint64_t i=0; i< size; i++){
        uint32_t this_addr = addr + i;
        taint2_labelset_ram_iter(abs_addr + i, callback, &this_addr);
    }

    return 1;
}

/**
 * Gets the current thread identifier on 32bit windows NT systems
 * Only works in user-space, where the FS segment points to the TIB
 * @see https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
 */
target_ulong getThreadID(CPUState* cpu){
    assert(!panda_in_kernel(cpu));

    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    target_ulong tib_address = env->segs[R_FS].base;
    target_ulong curr_thread_id_address = tib_address + 0x24;

    uint32_t curr_thread_id;
    panda_virtual_memory_read(cpu, curr_thread_id_address, (uint8_t*)(&curr_thread_id), 4);
    return curr_thread_id;
}

#ifdef TARGET_I386

/* When a sysenter is being executed, and we are about to jump in kernel-space.
Note this is only executed for interesting asid (filtering has been done on translate_callback) */
void onSysEnter(CPUState *cpu, target_ulong pc, const Syscall& sc){
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;

    // save up current_syscall to be used in write callback if no event is present
    //current_syscall = sc.callno;

    cout << sc.name << " while current_event was" << current_event << endl;
    if (!current_event){
        cout << "SYSENTER detected with no current event, tainting with syscall number" << endl;
        // TODO generate a new event instead, then pandalog events
    }
    
    //uint32_t taint_label = current_event != 0 ? current_event : sc.callno;

    //take size and location of syscall parameters
    //regs[R_EDX] + 8 points to the start of the syscall parameters
    uint64_t arg_start = env->regs[R_EDX] + 8;
    std::size_t arg_len = sc.paramSize();

    /* Taint should be enabled by the first interesting event.
       If it's not enabled, it means we haven't started tracking things yet */
    if(!taint2_enabled()){
        return;
    }

    /* Read taint for syscall args, the current event depends on the ones who
    tainted the arguments of the current syscall */
    cout << "Reading taint from " << arg_start << " to " << arg_start + arg_len << " from event " << current_event << endl;
    readLabels(cpu, arg_start, arg_len, currentEventDependencyAdder);
    cout << "done" << endl;

    // TODO taint EAX on sysExit (not required on windows, as return values are error messages)

    /* We now clear the taint from these arguments, and taint them again with
    the label of the current event. We do this to taint the pointers, so that 
    anytime this syscall uses them to write to memory, the result is also 
    tainted */ 
    /*
    cout << "Re-tainting ";
    uint64_t arg_start_pa = panda_virt_to_phys(cpu, arg_start);
    if(arg_start_pa == -1){
        cout << "ERROR panda_virt_to_phys errored" <<endl;
        return;
    }
    cout << "Tainting syscall args with " << taint_label << endl ;
    for(std::size_t i=0; i<arg_len; i++){
        taint2_delete_ram(arg_start_pa + i);
        taint2_label_ram(arg_start_pa + i, taint_label);
    }*/
    //cout << "done" << endl;
}


#endif

void systaint_event_enter(CPUState *cpu, uint32_t event_label){

    cerr << "THREADID " << getThreadID(cpu) << endl;

    if(!current_event){
        cout << "EVENT enter " << event_label << " instcount " <<  rr_get_guest_instr_count() << endl;
        current_event = event_label;

    } else {
        // we ignore nested events (such as nested syscalls)
        // as the topmost one should give us the most information
        cout << "EVENT ignored " << event_label << " instcount " <<  rr_get_guest_instr_count()<< " current " << current_event << endl;
    }

    // Start tracking this process if not doing it already
    if(!tracked_asid){
        target_ulong asid = panda_current_asid(cpu);
        cout << "TRACKING " << asid << " instcount " <<  rr_get_guest_instr_count() << endl;
        tracked_asid = asid;

        if (!taint2_enabled() && !no_llvm) {
            printf("enabling taint\n");
            taint2_enable_taint();
        }
    }
}

void systaint_event_exit(CPUState *cpu, uint32_t event_label){
    assert(event_label);
    assert(tracked_asid == panda_current_asid(cpu));

    if(current_event && event_label == current_event){
        cout << "EVENT exit " << event_label << " instcount " <<  rr_get_guest_instr_count() << endl;

        //labeling
        for(const auto& addr_data: current_event_memtracker.writeset){
            uint64_t write_pa = panda_virt_to_phys(cpu, addr_data.first);

            if(write_pa == -1){
                cout << "ERROR panda_virt_to_phys errored while labeling " << addr_data.first << " with " << event_label << endl;
            } else {
                taint2_label_ram(write_pa, current_event);
            }
        }

        //logging
        logSysFnCall(current_event, 0, current_event_memtracker, outfp);

        //resetting memtracker and event
        current_event_memtracker.clear();
        current_event = 0;

    } else if(current_event) {
        cout << "EVENT ignored_exit " << event_label << " instcount " <<  rr_get_guest_instr_count() << endl;
    } else {
        cerr << "WARNING exit from unexpected event " << event_label << " instcount " <<  rr_get_guest_instr_count() << endl;
    }
}


// ======================== 
// Encoding function calls handling
// ========================


// current encoding call, to use as taint label
uint32_t current_encoding_call_ = 0;
CallMemAccessTracker current_call_memtracker;


uint32_t getCurrentEncodingCall(CPUState* cpu){
    // TODO check thread
    return current_encoding_call_;
}

void on_call(CPUState *cpu, target_ulong entrypoint, uint64_t callid){
    if (panda_in_kernel(cpu) || tracked_asid != panda_current_asid(cpu)){
        return;
    }

    if(entrypoint == tracked_encoding_fn){
        cout << "CALL " << entrypoint << " " << callid << endl;
        current_encoding_call_ = callid;

    } else if(current_encoding_call_) {
        cerr << "WARNING detected call from an encoding call, currently not supported" << endl;
    }
}

void on_return(CPUState *cpu, target_ulong entrypoint, uint64_t callid,
               uint32_t skipped_frames){

    if (panda_in_kernel(cpu) || tracked_asid != panda_current_asid(cpu)){
        return;
    }

    if(current_encoding_call_ != callid){
        return;
    }

    // The current encoding call is returning
    // label its data
    for(const auto& addr_data: current_call_memtracker.writeset){
        uint64_t write_pa = panda_virt_to_phys(cpu, addr_data.first);

        if(write_pa == -1){
            cout << "ERROR panda_virt_to_phys errored while labeling " << addr_data.first << " with " << callid << endl;
        } else {
            taint2_label_ram(write_pa, current_encoding_call_);
        }
    }

    logSysFnCall(callid, entrypoint, current_call_memtracker, outfp);
    current_call_memtracker.clear();
    current_encoding_call_ = 0;
}


// ======================== 
// Memory access tracking 
// ========================

int currentEncodingCallDependencyAdder(uint32_t dependency, void *addressp){
    target_ulong addr = *(target_ulong*) addressp;

    if(dependency == current_encoding_call_){
        return 0;
    }

    if (eventDependencies[current_encoding_call_].count(dependency) == 0){
        printf("adding dependency %u -> %u \n", dependency, current_encoding_call_);
        eventDependencies[current_encoding_call_].insert(dependency);
    }

    current_call_memtracker.readdep(addr, dependency);
    return 0;
}

int mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    uint8_t* data = reinterpret_cast<uint8_t*>(buf);

    if (tracked_asid != panda_current_asid(cpu) || !isUserSpaceAddress(addr)){
        return 0;
    }

    uint32_t addr_pa = panda_virt_to_phys(cpu, addr);
    if(addr_pa == -1){
        cerr << "error in panda_virt_to_phys" << addr << endl;
        return 0;
    }

    /* Attempt
    In theory we don't need to taint memory for syscalls, as we are already tainting the
    pointers given as arguments. Let's try with this enabled anyway */

    if(current_event){
        for(target_ulong i=0; i<size; i++){
            current_event_memtracker.write(addr+i, data[i]);
        }
    }

    uint32_t curr_encoding_call = getCurrentEncodingCall(cpu);
    if(curr_encoding_call){
        cout << "CURRENT ENCODING FN WRITE " << curr_encoding_call << endl;

        for(target_ulong i=0; i<size; i++){
            current_call_memtracker.write(addr+i, data[i]);
        }
    }
    
    return 0;
}

int mem_read_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    uint8_t* data = reinterpret_cast<uint8_t*>(buf);

    if (tracked_asid != panda_current_asid(cpu)) {
        return 0;
    }

    // If there's a syscall currently executing, track its reads to find dependencies
    // from previous syscalls
    if(current_event && isUserSpaceAddress(addr)){
        for(target_ulong i=0; i< size; i++){
            current_event_memtracker.read(addr +i ,  data[i]);
        }
        readLabels(cpu, addr, size, currentEventDependencyAdder);
    }

    // If there's an encoding call currently executing, track its reads to find dependecies
    // and save the data that it's being read
    uint32_t current_encoding_function = getCurrentEncodingCall(cpu);
    if(current_encoding_function && current_event){
        cerr << "WARNING, both current_encoding_function and current_event are set" << endl;
    }

    if(current_encoding_function){
        cout << "CURRENT ENCODING FN READ" << endl;

        for(uint64_t i=0; i< size; i++){
            current_call_memtracker.read(addr + i, data[i]);
        }

        readLabels(cpu, addr, size, currentEncodingCallDependencyAdder);
    }

    return 0;
}

#endif // TARGET_I386

FILE* taintchanges = nullptr;

void on_taint_change (Addr ma, uint64_t size){
    (void)size;
    if(ma.typ == MADDR){
        fprintf(taintchanges, "%p %u\n", (void*)ma.val.ma, taint2_query_ram(ma.val.ma));
    };
}

void *plugin_self;

bool init_plugin(void *self) {
 
#ifdef TARGET_I386
    plugin_self = self;
    panda_cb pcb;

    panda_enable_memcb();

    pcb.virt_mem_after_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);
    pcb.virt_mem_after_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);
    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

    panda_require("taint2");
    assert(init_taint2_api());
    PPP_REG_CB("taint2", on_taint_change, on_taint_change);

    taintchanges = fopen("/tmp/taintchanges.log", "w");
    assert(taintchanges);

    panda_require("callstack_instr");
    assert(init_callstack_instr_api());

    string fname = "windows7_x86_prototypes.txt";
    parseSyscallDefs(fname);

    PPP_REG_CB("callstack_instr", on_call2, on_call);
    PPP_REG_CB("callstack_instr", on_ret2, on_return);

    panda_require("sysevent");
    PPP_REG_CB("sysevent", on_sysevent_enter, systaint_event_enter);
    PPP_REG_CB("sysevent", on_sysevent_exit, systaint_event_exit);

    panda_arg_list *args = panda_get_args("systaint");
    if (args != NULL) {
        tracked_asid = panda_parse_uint64_opt(args, "asid", 0, "asid to track");
        tracked_encoding_fn = panda_parse_uint64_opt(args, "encfn",  0, "encoding function to track");
        no_llvm = panda_parse_bool_opt(args, "no_llvm", "disable llvm and tainting");
        outfile = panda_parse_string_opt(args, "outfile", nullptr, "an output file");
    }

    if(outfile){
        outfp = fopen(outfile, "w");
    }

    if(tracked_encoding_fn){
        cout << "tracking encfn " << tracked_encoding_fn << endl;
    }

#endif

    return true;
}


void printOutDeps(){
    for (auto& it : eventDependencies){
        uint32_t to = it.first;
        const dependencySet& depset = it.second;

        for (auto& from : depset){
            printf("DEPENDENCY %u %u \n", from, to);
        }
    }
}


void uninit_plugin(void *self) {
    #ifdef TARGET_I386

    printOutDeps();

    if(outfp){
        fclose(outfp);
    }

    #endif
}

