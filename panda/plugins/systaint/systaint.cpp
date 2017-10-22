/**
* This plugin listens for several kinds of events (hypercalls, systemcalls,
* selected function calls) and employs taint analysis to build a dependency 
* graph between them. It also provides infos about the buffers used by each 
* event, and the provenance of each byte.
*/

#include "panda/plugin.h" //include plugin api we are implementing
#include "taint2/taint2.h" //include taint2 module we'll use
#include "callstack_instr/callstack_instr.h"
#include "sysevent/sysevent.h"
#include "syscall_listener.hpp"
#include <libgen.h>

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

#include "event.hpp"
#include "logging.hpp"
#include "introspection.hpp"

using namespace std;
using EventID = uint32_t;
using Asid = target_ulong;
using Address = target_ulong;
using dependencySet = std::unordered_set<EventID>;

class EventTracker {

public:
    std::map<FQThreadId, std::vector<shared_ptr<Event>>> curr_events;
    std::map<FQThreadId, std::vector<uint32_t>> curr_tags;

    std::shared_ptr<Event> getEvent(FQThreadId thread_id){
        auto& events = curr_events[thread_id];
        if(events.size()){
            return curr_events[thread_id].back();
        } else {
            return nullptr;
        }
    }

    std::vector<uint32_t>& getTags(FQThreadId thread_id){
        return curr_tags[thread_id];
    }

    void put_event(FQThreadId thread_id, shared_ptr<Event> event){
        event->thread = thread_id;
        auto& events = curr_events[thread_id];
        if(events.size()){
            event->parent = events.back()->getLabel();
        }
        events.push_back(event);
    }

    void closeEvent(FQThreadId thread_id, Event& event){
        auto& events = curr_events[thread_id];
        events.erase(std::find_if(events.begin(), events.end(),
                                    [&event](const shared_ptr<Event>& cev){
                                           return cev->label == event.label;
                                    }),
                                    events.end());

    }
};


//static std::map<EventID, dependencySet> eventDependencies;

#ifdef TARGET_I386

// ARGS:
//////////////////

// whether we want to run without LLVM and taint analysis
static bool no_llvm = false;

// filename where to print the function call data we collect
static const char* outfile = nullptr;

static bool automatically_add_processes = false;

// Globals:
//////////////

// Opened filepointer for writing collected function data
static FILE* outfp = nullptr;

std::set<Asid> monitored_processes;
static std::set<Address> monitored_encoding_calls;

static FQThreadId getFQThreadId(CPUState* cpu){
    return std::make_pair(panda_current_asid(cpu), get_current_thread_id(cpu));
}

static EventTracker events;

/** Reads the labels for a given memory range, executing the callback function for each*/
int readLabels(CPUState* cpu, target_ulong addr, target_ulong size, std::function<void(uint32_t, uint32_t)> callback){
    if(!taint2_enabled()) return 0;

    uint64_t abs_addr = panda_virt_to_phys(cpu, addr);
    if(abs_addr == static_cast<uint64_t>(-1)){
        cerr << "panda_virt_to_phys " << addr << " errored" << endl;
        return 0;
    }

    for(uint64_t i=0; i< size; i++){
        uint64_t abs_addr_i = abs_addr+i;
        uint32_t nlabels = taint2_query_ram(abs_addr_i);
        if(!nlabels) continue;

        vector<uint32_t> labels(nlabels);
        taint2_query_set_ram(abs_addr_i, labels.data());

        for(uint32_t label : labels){
            callback(static_cast<target_ulong>(addr + i), label);
        }
    }

    return 1;
}

#ifdef TARGET_I386

static void finalize_current_event(CPUState* cpu, FQThreadId thread){
    auto event = events.getEvent(thread);
    assert(event);

    // finalizing
    event->ended = rr_get_guest_instr_count();

    cout << "EVENT exit " << event->toString() << endl;

    //labeling
    for(const auto& addr_data: event->memory.writeset){
        uint64_t write_pa = panda_virt_to_phys(cpu, addr_data.first);

        if(write_pa == static_cast<uint64_t>(-1)){
            cerr << "ERROR panda_virt_to_phys errored while labeling " << addr_data.first << " with " << event->getLabel() << endl;
            break;
        } else {
            if(taint2_enabled()){
                taint2_label_ram(write_pa, event->getLabel());
            }
        }
    }

    //logging
    logEvent(*event, outfp);
    events.closeEvent(thread, *event);
}

/**
 * When a sysenter is being executed, and we are about to jump in kernel-space.
 */
void on_syscall_enter(CPUState *cpu, const SyscallDef& sc, SysCall call){



    if(call.syscall_no == 60 || // Skip NTContinue, which doesn't return
       call.syscall_no == 19 || // Skip NtAllocateVirtualMemory which is responsible for most noise
       call.syscall_no == 131){ // Skip NtFreeVirtualMemory (for simmetry)
        return;
    }

    FQThreadId thread = getFQThreadId(cpu);

    //Filtering is already done on instruction exec callback

    auto current_event = events.getEvent(thread);
    auto& current_tags = events.getTags(thread);

    if(current_event){
        cout << "SYSENTER ENCOUNTERED " << sc.name << " while current_event was" << current_event->toString() << endl;
    }

    cout << "SYSENTER " << sc.name << endl;
    auto new_event = make_shared<Event>();
    new_event->kind = EventKind::syscall;
    new_event->entrypoint = static_cast<uint32_t>(sc.callno);
    new_event->started = call.start;
    events.put_event(thread, new_event);

    if(current_tags.size()){
        cout << "current_tag " << current_tags[0] << endl;
        new_event->tags = current_tags;
    }


    /* Fine grained tainting (only taint arguments)
     * disabled for now in favor of tainting all memory accesses */
#if 0
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    if(!taint2_enabled())
        return;

    //take size and location of syscall parameters
    uint64_t arg_start = env->regs[R_EDX] + 8;
    std::size_t arg_len = sc.paramSize();

    //cout << "Reading taint from " << arg_start << " to " << arg_start + arg_len << " from event " << current_event << endl;
    //readLabels(cpu, arg_start, arg_len, currentEventDependencyAdder);

    // TODO taint EAX on sysExit (not required on windows, as return values are error messages)

    /* We now clear the taint from these arguments, and taint them again with
    the label of the current event. We do this to taint the pointers, so that 
    anytime this syscall uses them to write to memory, the result is also 
    tainted */ 

    uint64_t arg_start_pa = panda_virt_to_phys(cpu, arg_start);
    if(arg_start_pa == -1){
        cout << "ERROR panda_virt_to_phys errored" <<endl;
        return;
    }
    cout << "Tainting syscall args with " << taint_label << endl ;
    for(std::size_t i=0; i<arg_len; i++){
        taint2_delete_ram(arg_start_pa + i);
        taint2_label_ram_additive(arg_start_pa + i, taint_label);
    }
#endif
}

void on_syscall_exit(CPUState *cpu, const SyscallDef& sc, SysCall call){
    (void) sc;

    FQThreadId thread = getFQThreadId(cpu);
    auto current_event = events.getEvent(thread);

    if(!current_event){
        cerr << "WARNING sysexit without any current event" << endl;
        return;
    }

    if(current_event->kind != EventKind::syscall || current_event->started != call.start){
        cout << "SYSCALL ignoring exit" << endl;
        return;
    }

    cout << "SYSCALL EVENT exit " << current_event->toString() << endl;
    finalize_current_event(cpu, thread);

}

#endif


/**
 * @brief allows insertion of external events
 * @param cpu
 * @param event_label
 */
void external_event_enter(CPUState *cpu, uint32_t event_label){
    assert(cpu);
    assert(event_label);

    // Start tracking this process if not doing it already
    target_ulong asid = panda_current_asid(cpu);

    if(!monitored_processes.count(asid)){
        if(automatically_add_processes){
            cout << "TRACKING " << asid << " instcount " <<  rr_get_guest_instr_count() << endl;
            monitored_processes.insert(asid);

            //TODO
            //don't know why it is needed. Apparently some tbs are marked as translated
            //and don't go into syscall_listener's translate callback again
            panda_do_flush_tb();
        } else {
            return;
        }
    }

    FQThreadId thread = getFQThreadId(cpu);
    auto current_event = events.getEvent(thread);
    auto& current_tags = events.getTags(thread);
    current_tags.push_back(event_label);

    cout << "external event: " << event_label << " instcount " <<  rr_get_guest_instr_count() << endl;

#if 0
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
#endif

    if (!taint2_enabled() && !no_llvm) {
        printf("enabling taint\n");
        taint2_enable_taint();
    }
}

void external_event_exit(CPUState *cpu, uint32_t event_label){
    assert(cpu);
    assert(event_label);

    target_ulong asid = panda_current_asid(cpu);
    if(!monitored_processes.count(asid) && !automatically_add_processes){
        return;
    }

    auto thread = getFQThreadId(cpu);
    auto current_event = events.getEvent(thread);
    auto& current_tags = events.getTags(thread);

    //if(!current_event){
    //    cerr << "WARNING exit from unexpected event " << event_label << " instcount " <<  rr_get_guest_instr_count() << endl;
    //    return;
    //}

    // Remove all tags started after the one terminating (vector is sorted)
    current_tags.erase(std::find(current_tags.begin(), current_tags.end(), event_label), current_tags.end());

    if(current_event && current_event->kind == EventKind::external && event_label == current_event->label){
        finalize_current_event(cpu, thread);
    } else {
        cout << "external event ignored_exit " << event_label << " instcount " <<  rr_get_guest_instr_count() << endl;
    }
}


// ======================== 
// Encoding function calls handling
// ========================


void on_function_call(CPUState *cpu, target_ulong entrypoint, uint64_t callid){
    if (panda_in_kernel(cpu) || !monitored_processes.count(panda_current_asid(cpu))){
        return;
    }

    if(monitored_encoding_calls.count(entrypoint)){

        auto thread = getFQThreadId(cpu);
        auto p_current_event = events.getEvent(thread);

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

void on_function_return(CPUState *cpu, target_ulong entrypoint, uint64_t callid,
               uint32_t skipped_frames){
    (void) entrypoint;
    (void) skipped_frames;

    if (panda_in_kernel(cpu)){
        return;
    }

    auto thread = getFQThreadId(cpu);
    auto p_current_event = events.getEvent(thread);

    if(p_current_event && p_current_event->started == callid){
        finalize_current_event(cpu, thread);
    }
}


// ======================== 
// Memory access tracking 
// ========================

int mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    (void) pc;

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
    (void) pc;

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

//FILE* taintchanges = nullptr;

//void on_taint_change (Addr ma, uint64_t size){
//    (void)size;
//    if(ma.typ == MADDR){
//        fprintf(taintchanges, "%p %u\n", (void*)ma.val.ma, taint2_query_ram(ma.val.ma));
//    };
//}


std::set<target_ulong> parse_addr_list(const char* addrs){
    std::set<target_ulong> res;
    if(!addrs) return res;

    char* arrt = strdup(addrs);

    char* pch = strtok(arrt, " ,;_");
    while (pch != NULL){
        res.insert(static_cast<target_ulong>(std::stoul(pch, nullptr, 0)));
        pch = strtok(NULL, " ,;_");
    }

    free(arrt);
    return res;
}

/*int asid_changed_callback(CPUState* cpu, uint32_t oldasid, uint32_t newasid){
    if(monitored_processes.count(newasid)){
        if (!taint2_enabled() && !no_llvm) {
            printf("enabling taint\n");
            taint2_enable_taint();
        }
    } else {
        if (taint2_enabled() && !no_llvm){
            taint2_
        }
    }
}*/

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

    pcb.insn_translate = sc_listener_translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

    pcb.insn_exec = sc_listener_exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

    pcb.before_block_exec = sc_listener_returned_check_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    //pcb.asid_changed = asid_changed_callback;
    //panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    panda_require("taint2");
    assert(init_taint2_api());

    //PPP_REG_CB("taint2", on_taint_change, on_taint_change);
    //taintchanges = fopen("/tmp/taintchanges.log", "w");
    //assert(taintchanges);

    panda_require("callstack_instr");
    assert(init_callstack_instr_api());

    /* TODO use relative path
     * extern const char *qemu_file;
     * char * dirn = strdup(qemu_file);
     * string dname(dirname(dirn));
     * string fname = dname + "/....windows7_x86_prototypes.txt";
     */

    parseSyscallDefs("windows7_x86_prototypes.txt");

    PPP_REG_CB("callstack_instr", on_call2, on_function_call);
    PPP_REG_CB("callstack_instr", on_ret2, on_function_return);

    panda_require("sysevent");
    PPP_REG_CB("sysevent", on_sysevent_enter, external_event_enter);
    PPP_REG_CB("sysevent", on_sysevent_exit, external_event_exit);

    panda_arg_list *args = panda_get_args("systaint");
    if (args != NULL) {

        const char* tracked_asids = panda_parse_string_opt(args, "asids", nullptr, "list of asids to track");
        if(tracked_asids){
            if(!strcmp(tracked_asids, "auto")){
                automatically_add_processes = true;
            } else {
                monitored_processes = parse_addr_list(tracked_asids);
            }
        }

        const char* tracked_encoding_fn = panda_parse_string_opt(args, "encfns", nullptr, "list of encoding function addresses");
        if(tracked_encoding_fn)
            monitored_encoding_calls = parse_addr_list(tracked_encoding_fn);

        no_llvm = panda_parse_bool_opt(args, "no_llvm", "disable llvm and tainting");
        cout << "no_llvm " << no_llvm << endl;

        //fast = panda_parse_bool_opt(args, "fast", "turn on and off taint when asid changes");
        outfile = panda_parse_string_opt(args, "outfile", nullptr, "an output file");
    }

    if(outfile){
        outfp = fopen(outfile, "w");
        if(!outfp){
            perror("unable to open output file");
            exit(-1);
        }
    }

    for(const auto&i : monitored_encoding_calls){
        cout << "tracking encfn " << i << endl;
    }

    for(const auto&i : monitored_processes){
        cout << "tracking process " << i << endl;
    }

    panda_do_flush_tb();
    panda_enable_precise_pc();
    panda_enable_tb_chaining();

#endif

    return true;
}


//void printOutDeps(){
//    for (auto& it : eventDependencies){
//        uint32_t to = it.first;
//        const dependencySet& depset = it.second;

//        for (auto& from : depset){
//            printf("DEPENDENCY %u %u \n", from, to);
//        }
//    }
//}


void uninit_plugin(void *self) {
    #ifdef TARGET_I386

    // handle unterminated events

    cout << "UNTERMINATED " << endl;

    for(const auto& thread_event : events.curr_events){
        //const auto& t = thread_event.first;
        const auto& evs = thread_event.second;

        for(const auto& e : evs){
            std::cout << e->toString() << std::endl;
            logEvent(*e, outfp);
        }
    }

    //printOutDeps();

    if(outfp){
        fclose(outfp);
    }

    #endif
}

