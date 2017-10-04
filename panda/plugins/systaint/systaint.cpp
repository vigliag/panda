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
#include <functional>
#include <memory>

using namespace std;

#include "event.hpp"
#include "logging.hpp"
#include "introspection.hpp"

// Dependency tree we are going to build
using dependencySet = std::unordered_set<uint32_t>;
static std::map<uint32_t, dependencySet> eventDependencies;

Addr make_maddr(uint64_t a) {
    Addr ma;
    ma.typ = MADDR;
    ma.val.ma = a;
    ma.off = 0;
    ma.flag = (AddrFlag) 0;
    return ma;
}

#ifdef TARGET_I386

static bool no_llvm = false;
static const char* outfile = nullptr;
static FILE* outfp = nullptr;

std::set<uint32_t> monitored_processes;
std::set<uint32_t> monitored_encoding_calls;

static FQThreadId getFQThreadId(CPUState* cpu){
    return std::make_pair(panda_current_asid(cpu), get_current_thread_id(cpu));
}

class EventTracker {
    std::map<FQThreadId, shared_ptr<Event>> curr_event;
public:
    std::shared_ptr<Event> getEvent(FQThreadId thread_id){
        return curr_event[thread_id];
    }
    void put_event(FQThreadId thread_id, shared_ptr<Event> event){
        curr_event[thread_id] = event;
    }
    void closeEvent(FQThreadId thread_id){
        curr_event.erase(thread_id);
    }
};

EventTracker events;

/* Used as a callback to add new_label as a dependency to this_label
   uses global data structures */
/*
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
}*/

int readLabels(CPUState* cpu, target_ulong addr, target_ulong size, std::function<void(uint32_t, uint32_t)> callback){
    if(!taint2_enabled()) return 0;

    uint64_t abs_addr = panda_virt_to_phys(cpu, addr);
    if(abs_addr == static_cast<uint64_t>(-1)){
        cerr << "panda_virt_to_phys " << addr << " errored" << endl;
        return 0;
    }

    for(uint64_t i=0; i< size; i++){
        LabelSetP ls = taint2_labelset_addr_query(make_maddr(abs_addr+i));

        if(!ls) continue;

        for(uint32_t label : *ls){
            callback(addr + i, label);
        }
    }

    return 1;
}

#ifdef TARGET_I386

/* When a sysenter is being executed, and we are about to jump in kernel-space.
Note this is only executed for interesting asid (filtering has been done on translate_callback) */
void onSysEnter(CPUState *cpu, const SyscallDef& sc, SysCall call){


    FQThreadId thread = getFQThreadId(cpu);
    auto current_event = events.getEvent(thread);

    if(current_event){
        cout << sc.name << " while current_event was" << current_event->toString() << endl;
    } else {
        cout << "SYSENTER detected with no current event, creating syscall event" << endl;
        current_event = make_shared<Event>();
        current_event->kind = EventKind::syscall;
        current_event->entrypoint = sc.callno;
        current_event->started = rr_get_guest_instr_count();
        events.put_event(thread, current_event);
    }


    /*

    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    // Read taint for syscall args, the current event depends on the ones who
    // tainted the arguments of the current syscall
    if(!taint2_enabled()){
        return;
    }

    //take size and location of syscall parameters
    //regs[R_EDX] + 8 points to the start of the syscall parameters
    uint64_t arg_start = env->regs[R_EDX] + 8;
    std::size_t arg_len = sc.paramSize();

    //cout << "Reading taint from " << arg_start << " to " << arg_start + arg_len << " from event " << current_event << endl;
    //readLabels(cpu, arg_start, arg_len, currentEventDependencyAdder);
    //cout << "done" << endl;

    */

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

void onEventEnd(CPUState* cpu, FQThreadId thread){
    auto event = events.getEvent(thread);
    assert(event);

    event->ended = rr_get_guest_instr_count();

    cout << "EVENT exit " << event->toString() << endl;

    //labeling
    for(const auto& addr_data: event->memory.writeset){
        uint64_t write_pa = panda_virt_to_phys(cpu, addr_data.first);

        if(write_pa == -1){
            cout << "ERROR panda_virt_to_phys errored while labeling " << addr_data.first << " with " << event->getLabel() << endl;
        } else {
            if(!no_llvm) taint2_label_ram(write_pa, event->getLabel());
        }
    }

    //logging
    logEvent(*event, outfp);
    events.closeEvent(thread);
}


void onSysExit(CPUState *cpu, const SyscallDef& sc, SysCall call){
    FQThreadId thread = getFQThreadId(cpu);
    auto current_event = events.getEvent(thread);

    if(!current_event){
        cerr << "WARNING sysexit without any current event" << endl;
        return;
    }

    if(current_event->kind != EventKind::syscall){
        cout << "SYSCALL ignoring exit (current event has precedence) " << endl;
        return;
    }

    cout << "SYSCALL EVENT exit " << current_event->toString() << endl;
    onEventEnd(cpu, thread);

}

#endif


/**
 * @brief systaint_event_enter allows insertion of external events
 * @param cpu
 * @param event_label
 */
void systaint_event_enter(CPUState *cpu, uint32_t event_label){
    assert(cpu);
    assert(event_label);

    FQThreadId thread = getFQThreadId(cpu);

    auto current_event = events.getEvent(thread);
    if(!current_event){
        cout << "EVENT enter " << event_label << " instcount " <<  rr_get_guest_instr_count() << endl;

        current_event = make_shared<Event>();
        current_event->entrypoint = event_label;
        current_event->started = rr_get_guest_instr_count();
        current_event->kind = EventKind::external;
        current_event->label = event_label;
        events.put_event(thread, current_event);

    } else {
        // we ignore nested events (such as nested syscalls)
        // as the topmost one should give us the most information
        cout << "EVENT ignored " << event_label << " instcount " <<  rr_get_guest_instr_count()<< " current " << current_event->toString() << endl;
    }

    // Start tracking this process if not doing it already
    target_ulong asid = panda_current_asid(cpu);
    if(!monitored_processes.count(asid)){
        cout << "TRACKING " << asid << " instcount " <<  rr_get_guest_instr_count() << endl;
        monitored_processes.insert(asid);
    }

    if (!taint2_enabled() && !no_llvm) {
        printf("enabling taint\n");
        taint2_enable_taint();
    }
}

void systaint_event_exit(CPUState *cpu, uint32_t event_label){
    assert(cpu);
    assert(event_label);

    auto thread = getFQThreadId(cpu);
    auto current_event = events.getEvent(thread);

    if(!current_event){
        cerr << "WARNING exit from unexpected event " << event_label << " instcount " <<  rr_get_guest_instr_count() << endl;
        return;
    }

    if(event_label == current_event->label){
        onEventEnd(cpu, thread);
    } else {
        cout << "EVENT ignored_exit " << event_label << " instcount " <<  rr_get_guest_instr_count() << endl;
    }
}


// ======================== 
// Encoding function calls handling
// ========================


void on_call(CPUState *cpu, target_ulong entrypoint, uint64_t callid){
    if (panda_in_kernel(cpu) || !monitored_processes.count(panda_current_asid(cpu))){
        return;
    }

    auto thread = getFQThreadId(cpu);
    auto p_current_event = events.getEvent(thread);


    if(monitored_encoding_calls.count(entrypoint)){

        if(p_current_event){
            cerr << "encoding call during existing event. This shouldn't happen. "
                 << entrypoint << " " << callid << " -- " << p_current_event->toString() << endl;
            return;
        }

        cout << "CALL " << entrypoint << " " << callid << endl;

        auto event = make_shared<Event>();
        event->kind = EventKind::encoding;
        event->entrypoint = entrypoint;
        event->thread = thread;
        event->started = callid;

        events.put_event(thread, event);
    }
}

void on_return(CPUState *cpu, target_ulong entrypoint, uint64_t callid,
               uint32_t skipped_frames){

    if (panda_in_kernel(cpu)){
        return;
    }

    auto thread = getFQThreadId(cpu);
    auto p_current_event = events.getEvent(thread);

    if(p_current_event && p_current_event->started == callid){
        onEventEnd(cpu, thread);
    }
}


// ======================== 
// Memory access tracking 
// ========================

int mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    uint8_t* data = reinterpret_cast<uint8_t*>(buf);

    if (!monitored_processes.count(panda_current_asid(cpu)) || !isUserSpaceAddress(addr)){
        return 0;
    }

    auto thread = getFQThreadId(cpu);
    auto p_current_event = events.getEvent(thread);

    if(p_current_event){
        for(target_ulong i=0; i<size; i++){
            p_current_event->memory.write(addr+i, data[i]);
        }
    }
    
    return 0;
}

int mem_read_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    uint8_t* data = reinterpret_cast<uint8_t*>(buf);

    if (!monitored_processes.count(panda_current_asid(cpu))) {
        return 0;
    }

    auto thread = getFQThreadId(cpu);
    auto p_current_event = events.getEvent(thread);

    // If there's an event currently executing, track its reads to find dependencies
    // from previous syscalls
    if(p_current_event && isUserSpaceAddress(addr)){

        for(target_ulong i=0; i< size; i++){
            p_current_event->memory.read(addr +i ,  data[i]);
        }

        readLabels(cpu, addr, size, [&p_current_event](uint32_t addr, uint32_t dep){
            p_current_event->memory.readdep(addr, dep);
        });

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
    pcb.before_block_exec = returned_check_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

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
        uint64_t tracked_asid = panda_parse_uint64_opt(args, "asid", 0, "asid to track");
        uint64_t tracked_encoding_fn = panda_parse_uint64_opt(args, "encfn",  0, "encoding function to track");
        monitored_processes.insert(tracked_asid);
        monitored_encoding_calls.insert(tracked_encoding_fn);
        no_llvm = panda_parse_bool_opt(args, "no_llvm", "disable llvm and tainting");
        outfile = panda_parse_string_opt(args, "outfile", nullptr, "an output file");
    }

    if(outfile){
        outfp = fopen(outfile, "w");
    }

    for(const auto&i : monitored_encoding_calls){
        cout << "tracking encfn " << i << endl;
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

