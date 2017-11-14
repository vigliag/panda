/**
* This plugin listens for several kinds of events (hypercalls, systemcalls,
* selected function calls) and employs taint analysis to build a dependency 
* graph between them. It also provides infos about the buffers used by each 
* event, and the provenance of each byte.
*/

#include "panda/plugin.h" //include plugin api we are implementing
//#include "taint2/taint2.h" //include taint2 module we'll use
#include "callstack_instr/callstack_instr.h"
#include "sysevent/sysevent.h"
#include "syscall_listener.hpp"
#include <libgen.h>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C

extern "C" {

//#include "taint2/taint2_ext.h"
#include "tcgtaint/tcgtaint_ext.h"
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
using Tag = uint32_t;
using Label = uint32_t;


// Opened filepointer for writing the collected data
static FILE* outfp = nullptr;

//using dependencySet = std::unordered_set<EventID>;

class EventTracker {

public:
    /** per-thread stack of current events */
    std::map<FQThreadId, std::vector<shared_ptr<Event>>> curr_events;
    /** per-thread stack of current tags */
    std::map<FQThreadId, std::vector<Tag>> curr_tags;

    std::shared_ptr<Event> getEvent(FQThreadId thread_id){
        std::vector<shared_ptr<Event>>& events = curr_events[thread_id];
        if(events.size()){
            return curr_events[thread_id].back();
        } else {
            return nullptr;
        }
    }

    std::vector<Tag>& getTags(FQThreadId thread_id){
        return curr_tags[thread_id];
    }

    void put_event(const FQThreadId& thread_id, shared_ptr<Event> event){
        event->thread = thread_id;
        auto& existing_events = curr_events[thread_id];
        if(existing_events.size()){
            event->parent = existing_events.back()->getLabel();
        }
        existing_events.push_back(event);
    }

    void closeEvent(const FQThreadId &thread_id, Event &event) {
      auto &events = curr_events[thread_id];
      // remove all events above the current one from the event stack
      // TODO those events should be logged, not discarded
      auto closing_evnt_it = std::find_if(
          events.begin(), events.end(), [&event](const shared_ptr<Event> &cev) {
            return cev->getLabel() == event.getLabel();
          });

      for(auto it = closing_evnt_it; it != events.end(); it++){
          logEvent(**it, outfp);
      }
      events.erase(closing_evnt_it, events.end());
    }
};


//static std::map<EventID, dependencySet> eventDependencies;

#ifdef TARGET_I386

// ARGS:
//////////////////

// whether we want to run without LLVM and taint analysis
static bool dont_enable_taint = false;


static bool no_callstack = false;

// filename where to print the collected data
static const char* outfile = nullptr;

static bool automatically_add_processes = false;

static bool extevents_as_primary = false;
static bool only_taint_syscall_args = false;
static bool use_candidate_pointers = false;
static bool no_syscalls = false;
static const bool defer_tainting_writes_to_end_of_the_block = false;
static bool debug_logs = false;
static bool disable_taint_on_other_processes = false;

static uint64_t target_end_count = 0;
static uint64_t target_taint_at = 0;

// Globals:
//////////////


std::set<Asid> monitored_processes; //shared with syscall_listener

static std::set<Address> monitored_encoding_calls;

static FQThreadId getFQThreadId(CPUState* cpu){
    return std::make_pair(panda_current_asid(cpu), get_current_thread_id(cpu));
}

static EventTracker events;

static std::set<hwaddr> phisicalAddressesToTaint;

static uint32_t next_available_label = 0;

// Wrappers:


static void enableTaint(){
    //taint2_enable_taint();
    tcgtaint_set_taint_status(true);
}

static int taintEnabled(){
    //return taint2_enabled();
    return tcgtaint_is_taint_enabled();
}

/** Reads the labels for a given memory range, executing the callback function for each */
static int readLabels(CPUState* cpu, Address addr, target_ulong size, std::function<void(Address, Label)> callback){
    if(!taintEnabled()) return 0;

    uint64_t abs_addr = panda_virt_to_phys(cpu, addr);
    if(abs_addr == static_cast<uint64_t>(-1)){
        cerr << "panda_virt_to_phys " << addr << " errored while reading labels" << endl;
        return 0;
    }

    for(uint32_t i=0; i< size; i++){
        uint64_t abs_addr_i = abs_addr+i;

        uint32_t nlabels = tcgtaint_get_physical_memory_labels_count(abs_addr_i);
        //uint32_t nlabels = taint2_query_ram(abs_addr_i);


        if(!nlabels) continue;


        //vector<uint32_t> labels(nlabels);
        //taint2_query_set_ram(abs_addr_i, labels.data());

        vector<uint32_t> labels(nlabels);
        tcgtaint_physical_memory_labels_copy(abs_addr_i, labels.data());

        if(debug_logs){
            fprintf(stderr, "READLABEL %u / %d at %d (%p) \n", labels[0], nlabels, addr +i, (void*)abs_addr_i);
        }

        for(uint32_t label : labels){
            callback(addr + i, label);
        }
    }

    return 1;
}

const bool LABEL_ADDITIVE = true;

static void writeLabelPA(uint64_t pa_addr, size_t size, Label label, bool additive = false){
    if(!taintEnabled())
        return;

    for(size_t i = 0; i < size; i++){
        if(additive){
            //taint2_label_ram_additive(pa_addr + i, label);
            tcgtaint_taint_physical_memory(pa_addr+i, 1, label);
        } else {
            //taint2_label_ram(pa_addr +i, label);
            tcgtaint_clear_physical_memory(pa_addr+i, 1);
            tcgtaint_taint_physical_memory(pa_addr+i, 1, label);
        }
    }
}

#ifdef TARGET_I386

static void finalize_current_event(CPUState* cpu, FQThreadId thread){
    std::shared_ptr<Event> event = events.getEvent(thread);
    assert(event);

    // finalizing
    event->ended = rr_get_guest_instr_count();

    cout << "EVENT exit " << event->toString() << endl;

    if (!no_callstack) {
      std::vector<target_ulong> current_callstack(10);
      int callstacksize =
          get_functions(current_callstack.data(),
                      static_cast<int>(current_callstack.size()), cpu);
      current_callstack.resize(callstacksize);
      event->callstack = std::move(current_callstack);
    }

    //logging
    logEvent(*event, outfp);
    events.closeEvent(thread, *event);

    event = events.getEvent(thread);
    if(event){
        cout << "current event on thread " << thread.second << " is now: " << event->getLabel() << endl;
    }
}

bool syscall_to_discard(unsigned syscall_no) {
  switch (syscall_no) {
  case 371: // NtTerminateThread (non terminating)
  case 389: // NtWaitForMultipleObjects
  case 392: // NtWaitForWorkViaWorkerFactory
  case 98:  // NtDelayExecution
  case 391: // NtWaitForSingleObject
  case 287: // NtRemoveIoCompletion
  case 39:  // NtAlpcSendWaitReceivePort
  case 60:  // NTContinue, doesn't return
  case 19:  // NtAllocateVirtualMemory which is responsible for most noise
  case 131: // NtFreeVirtualMemory (for simmetry)
  case 267: // NtQueryVirtualMemory (noise)
  case 335: // NtSetInformationThread (outlier)
  case 44:
    return true;
  default:
    return false;
  }
}

/**
 * When a sysenter is being executed, and we are about to jump in kernel-space.
 */
void on_syscall_enter(CPUState *cpu, const SyscallDef& sc, SysCall call){

    if(syscall_to_discard(call.syscall_no)){
        return;
    }

    if(no_syscalls){
        return;
    }

    FQThreadId thread = getFQThreadId(cpu);

    //take size and location of syscall parameters
    CPUArchState *env = reinterpret_cast<CPUArchState*>(cpu->env_ptr);
    uint32_t arg_start = env->regs[R_EDX] + 8;
    std::size_t arg_len = sc.paramSize();

    //Filtering is already done on instruction exec callback

    std::shared_ptr<Event> current_event = events.getEvent(thread);
    auto& current_tags = events.getTags(thread);

    if (current_event) {
      cout << "SYSENTER ENCOUNTERED " << sc.callno << " " << sc.name
           << " while current_event was" << current_event->toString() << endl;
    }

    cout << "SYSENTER " << sc.callno << " " << sc.name << endl;
    auto new_event = make_shared<Event>();
    new_event->kind = EventKind::syscall;
    new_event->entrypoint = static_cast<uint32_t>(sc.callno);
    new_event->started = call.start;
    new_event->label = next_available_label++;

    if(use_candidate_pointers){
        new_event->knownDataPointers.insert(arg_start);
    }

    events.put_event(thread, new_event);

    if(current_tags.size()){
        cout << "current_tag " << current_tags[0] << endl;
        new_event->tags = current_tags;
    }

    /* Fine grained tainting (only taint arguments) */

    if(!only_taint_syscall_args || !taintEnabled()){
        return;
    }

    uint32_t taint_label = static_cast<uint32_t>(new_event->started);

    uint64_t arg_start_pa = panda_virt_to_phys(cpu, arg_start);
    if(arg_start_pa == static_cast<uint64_t>(-1)){
        cout << "ERROR panda_virt_to_phys errored while translating " << arg_start_pa << endl;
        return;
    }

    cout << "Tainting syscall args with " << taint_label << endl ;
    writeLabelPA(arg_start_pa, arg_len, taint_label, LABEL_ADDITIVE);

}

void on_syscall_exit(CPUState *cpu, const SyscallDef& sc, SysCall call){
    (void) sc;

    FQThreadId thread = getFQThreadId(cpu);
    auto current_event = events.getEvent(thread);

    if(syscall_to_discard(call.syscall_no)){
        return;
    }

    if(!current_event){
        cerr << "WARNING sysexit no=" << sc.callno << " without any current event thread=" << thread.second <<  endl;
        return;
    }

    if(current_event->kind != EventKind::syscall || current_event->started != call.start){
        cout << "SYSCALL ignoring exit" << endl;
        return;
    }

    // TODO taint EAX on sysExit (not required on windows, as return values are error messages)

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
        } else {
            return;
        }
    }

    FQThreadId thread = getFQThreadId(cpu);
    std::shared_ptr<Event> current_event = events.getEvent(thread);
    auto& current_tags = events.getTags(thread);

    cout << "external event: " << event_label << " instcount " <<  rr_get_guest_instr_count() << endl;

    if(!extevents_as_primary){
        current_tags.push_back(event_label);
    }

    if(extevents_as_primary){
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
    }


    if (!taintEnabled() && !dont_enable_taint && !target_taint_at) {
        printf("enabling taint\n");
        enableTaint();
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
    std::shared_ptr<Event> current_event = events.getEvent(thread);
    auto& current_tags = events.getTags(thread);

    //if(!current_event){
    //    cerr << "WARNING exit from unexpected event " << event_label << " instcount " <<  rr_get_guest_instr_count() << endl;
    //    return;
    //}

    // Remove all tags started after the one terminating (vector is sorted)
    current_tags.erase(std::find(current_tags.begin(), current_tags.end(), event_label), current_tags.end());

    if(current_event && current_event->kind == EventKind::external && event_label == current_event->getLabel()){
        finalize_current_event(cpu, thread);
    } else {
        cout << "external event ignored_exit " << event_label << " instcount " <<  rr_get_guest_instr_count();
        if(current_event){
            cout << " current event label " << current_event->getLabel();
        } else {
            cout << " no current event";
        }
        cout << endl;
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

        if(p_current_event && p_current_event->kind == EventKind::syscall){
            cerr << "encoding call during a syscall. This shouldn't happen. "
                 << entrypoint << " " << callid << " -- " << p_current_event->toString() << endl;
            return;
        }

        cout << "CALL " << entrypoint << " " << callid << endl;

        auto event = make_shared<Event>();
        event->kind = EventKind::encoding;
        event->entrypoint = entrypoint;
        event->thread = thread;
        event->started = callid;
        event->label = next_available_label++;

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

static bool addressIsNearCandidatePointer(const std::shared_ptr<Event>& p_curr_event, const target_ulong addr){
    auto it_after = p_curr_event->knownDataPointers.upper_bound(addr);

    if(it_after == p_curr_event->knownDataPointers.begin()){
        //can happen if .begin() == .end(), or if there's no smaller pointer
        puts("discard (no lower)");
        return false;
    } else {
        it_after--;

        target_ulong closest_known_pointer = *it_after;
        if (addr - closest_known_pointer >= 0x1000){
            //discard as the first candidate pointer is too distant
            puts("discard (too distant)");
            return false;
        }
    }

    return true;
}


int mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    (void) pc;
    if(debug_logs){
        cerr << "WRITE at " << addr << " size=" << size << endl;
    }

    uint8_t* data = reinterpret_cast<uint8_t*>(buf);

    if (!monitored_processes.count(panda_current_asid(cpu)) || !isUserSpaceAddress(addr)){
        return 0;
    }

    FQThreadId thread = getFQThreadId(cpu);
    auto p_current_event = events.getEvent(thread);

    if(p_current_event){
        hwaddr physical_address = panda_virt_to_phys(cpu, addr);
        bool translation_error = physical_address == static_cast<hwaddr>(-1);

        bool should_taint = true;

        if(translation_error){
            cerr << "Error when translating address " << addr << "to physical (won't taint)" << endl;
            should_taint = false;
        }

        if(p_current_event->kind != EventKind::encoding){
            if(only_taint_syscall_args){
                should_taint = false;
            } else if(use_candidate_pointers){
                should_taint = addressIsNearCandidatePointer(p_current_event, addr);
            }
        }

        for(target_ulong i=0; i<size; i++){
            p_current_event->memory.write(addr+i, data[i]);

            if(should_taint){

                if(debug_logs){
                    uint8_t printable = isprint(data[i]) ? data[i] : '_';
                    cerr << "LABELLING " << addr +i <<" (" << std::hex << physical_address + i << std::dec << ") " << char(printable) << endl;
                }

                if(defer_tainting_writes_to_end_of_the_block){
                    // defer tainting to end of the block. Useful for LLVM taint,
                    // which has instrumentation _after_ the store, and would immediately clear the taint
                    phisicalAddressesToTaint.insert(physical_address + i);
                } else {
                    writeLabelPA(physical_address+i, 1, p_current_event->getLabel(), false);
                }
            }
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

    if(!p_current_event || !isUserSpaceAddress(addr)){
        return 0;
    }

    // If there's an event currently executing, track its reads to find dependencies
    // from previous syscalls

    if(use_candidate_pointers){
        bool add_addr_to_candidate_pointers = addressIsNearCandidatePointer(p_current_event, addr);

        if(add_addr_to_candidate_pointers){
            uint32_t pointers_read = 0;
            uint32_t* ptrptr = reinterpret_cast<target_ulong*>(buf);

            // TODO not sure there's a point in reading more than a pointer at once
            while(size - pointers_read * sizeof(target_ulong) <= sizeof(target_ulong)){
                target_ulong ptr = ptrptr[pointers_read];
                p_current_event->knownDataPointers.insert(ptr);
                pointers_read++;
            }
        }
    }

    if(debug_logs){
        fprintf(stderr, "READ %d (%p) of %d bytes \n", addr, (void*)panda_virt_to_phys(cpu, addr), size);
    }

    for(target_ulong i=0; i< size; i++){
        p_current_event->memory.read(addr +i ,  data[i]);
    }

    readLabels(cpu, addr, size, [&p_current_event](uint32_t addri, uint32_t dep){
        p_current_event->memory.readdep(addri, dep);
    });

    return 0;
}

int systaint_after_block_callback(CPUState *cpu, TranslationBlock *tb){
    (void) tb;

    auto instr_count = rr_get_guest_instr_count();
    if(target_end_count && instr_count > target_end_count){
        rr_end_replay_requested = 1;
    } else if(target_taint_at && instr_count > target_taint_at && !dont_enable_taint && !taintEnabled()){
        enableTaint();
    }

    //deferred labeling
    if(defer_tainting_writes_to_end_of_the_block){
        FQThreadId thread = getFQThreadId(cpu);
        std::shared_ptr<Event> current_event = events.getEvent(thread);

        if(current_event && taintEnabled()){
            Label label = current_event->getLabel();
            for(const auto& addr: phisicalAddressesToTaint){
                writeLabelPA(addr, 1, label);
            }
        }

        phisicalAddressesToTaint.clear();
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

int asid_changed_callback(CPUState* cpu, uint32_t oldasid, uint32_t newasid){
    (void) cpu;
    (void) oldasid;

    if(monitored_processes.count(newasid)){
        if (!taintEnabled() && !dont_enable_taint) {
            printf("enabling taint\n");
            enableTaint();
        } else if(disable_taint_on_other_processes){
            tcgtaint_set_taint_status(false);
        }
    }

    return 0;
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

    pcb.insn_translate = sc_listener_translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

    pcb.insn_exec = sc_listener_exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

    pcb.before_block_exec = sc_listener_returned_check_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    pcb.after_block_exec = systaint_after_block_callback;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

    pcb.asid_changed = asid_changed_callback;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    //panda_require("taint2");
    //assert(init_taint2_api());

    panda_require("tcgtaint");
    assert(init_tcgtaint_api());

    //PPP_REG_CB("taint2", on_taint_change, on_taint_change);
    //taintchanges = fopen("/tmp/taintchanges.log", "w");
    //assert(taintchanges);



    /* TODO use relative path
     * extern const char *qemu_file;
     * char * dirn = strdup(qemu_file);
     * string dname(dirname(dirn));
     * string fname = dname + "/....windows7_x86_prototypes.txt";
     */

    parseSyscallDefs("windows7_x86_prototypes.txt");


    panda_require("sysevent");
    PPP_REG_CB("sysevent", on_sysevent_enter, external_event_enter);
    PPP_REG_CB("sysevent", on_sysevent_exit, external_event_exit);

    panda_arg_list *args = panda_get_args("systaint");
    if (args != NULL) {

        target_taint_at = panda_parse_uint64_opt(args, "taintat", 0, "instruction count when to enable tainting");
        target_end_count = panda_parse_uint64_opt(args, "endat", 0, "instruction count when to end the replay");

        only_taint_syscall_args = panda_parse_bool_opt(args, "only_syscall_args", "only taint syscall arguments");
        if(only_taint_syscall_args){
            std::cout << "Only tainting syscall args" << std::endl;
        }

        use_candidate_pointers = only_taint_syscall_args;
        if(use_candidate_pointers){
            std::cout << "Using candidate pointers" << std::endl;
        }

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

        dont_enable_taint = panda_parse_bool_opt(args, "no_taint", "disables automatically turning on tainting");
        cout << "no_taint " << dont_enable_taint << endl;

        disable_taint_on_other_processes = panda_parse_bool_opt(args, "no_taint_other", "toggles tainting on task switch");
        cout << "no_taint_other " << disable_taint_on_other_processes << endl;

        no_callstack = panda_parse_bool_opt(args, "no_callstack", "disable callstack instrumentation");
        cout << "no_callstack " << no_callstack << endl;

        if(!no_callstack){
            panda_require("callstack_instr");
            assert(init_callstack_instr_api());
            PPP_REG_CB("callstack_instr", on_call2, on_function_call);
            PPP_REG_CB("callstack_instr", on_ret2, on_function_return);
        }

        extevents_as_primary = panda_parse_bool_opt(args, "extevents", "use syscalls as primary events");

        no_syscalls = panda_parse_bool_opt(args, "no_syscalls", "don't track syscalls");
        if(no_syscalls){
            extevents_as_primary = true;
        }

        outfile = panda_parse_string_opt(args, "outfile", nullptr, "an output file");

        if(!outfile && !pandalog){
            std::cout << "Please pass an 'outfile' parameter, or enable pandalog" << std::endl;
            return false;
        }
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

    //TODO now probably useless
    panda_do_flush_tb();
    panda_enable_precise_pc();

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

