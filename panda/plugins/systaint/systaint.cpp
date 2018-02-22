/**
* This plugin listens for several kinds of events (hypercalls, systemcalls,
* selected function calls) and employs taint analysis to build a dependency 
* graph between them. It also provides infos about the buffers used by each 
* event, and the provenance of each byte.
*/

#pragma GCC diagnostic ignored "-Wformat-y2k"

#include "panda/plugin.h" //include plugin api we are implementing
//#include "taint2/taint2.h" //include taint2 module we'll use
#include "callstack_instr/callstack_instr.h"
#include "sysevent/sysevent.h"
#include "syscall_listener.hpp"
#include <libgen.h>
#include <json.hpp> //nlohmann json
#include <unistd.h> //getcwd
#include <fstream>
#include "../stringsearch2/searchmanager.h"

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
      auto closing_evnt_it = std::find_if(
          events.begin(), events.end(), [&event](const shared_ptr<Event> &cev) {
            return cev->getLabel() == event.getLabel();
          });

      // log all other events in between
      auto it = closing_evnt_it;
      it++; //skip current (already logged)
      for(; it != events.end(); it++){
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

// whether to exclude callstack information
static bool no_callstack = false;

// filename where to print the collected data
// static const char* outfile = nullptr;

// automatically add processes on hypercall
// set to true if no asid is specified
static bool automatically_add_processes = false;

// treat external events (hypercalls) as primary events
// (not as tags)
static bool extevents_as_primary = false;

// only taint arguments to the syscalls instead of
// all data written inside
static bool only_taint_syscall_args = false;

// try to recognize data pointed by syscall argument
static bool use_candidate_pointers = true;

// do not intercept syscalls, only extevents
static bool no_syscalls = false;

// taint at the end of each block. Needed when using taint2
// instead of tcgtaint
static const bool defer_tainting_writes_to_end_of_the_block = false;

// additional debugging logs
static bool debug_logs = false;

// turn off taint engine when switching to an untracked process
// experimental
static bool disable_taint_on_other_processes = false;

// log all function calls (tainted data only)
static bool log_common_function_calls = true;

// close replay at
static uint64_t target_end_count = 0;

// turn on tainting at
static uint64_t target_taint_at = 0;

static bool set_taint_dereference = false;

// Globals:
//////////////

std::set<Asid> monitored_processes; //shared with syscall_listener

static std::set<Address> monitored_encoding_calls;

static FQThreadId getFQThreadId(CPUState* cpu){
    return std::make_pair(panda_current_asid(cpu), get_current_thread_id(cpu));
}

static EventTracker events;

static std::set<hwaddr> phisicalAddressesToTaint;

static std::map<uint64_t, std::shared_ptr<Event>> commonFunctions;

//starting from 1000, so we can use the first 1000 for progressive notifications
static uint32_t next_available_label = 1000;

//stuff to search in ram
//if search is specified as parameter
std::vector<SearchInfo> searches;

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
            fprintf(stderr, "READLABEL lbl=%u / %d at %d (%p) \n", labels[0], nlabels, addr +i, (void*)abs_addr_i);
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

static void finalize_event(CPUState* cpu, std::shared_ptr<Event> event){
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
}

static void finalize_current_event(CPUState* cpu, FQThreadId thread){
    std::shared_ptr<Event> event = events.getEvent(thread);
    assert(event);

    // finalizing
    finalize_event(cpu,event);

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
  case 216: // NtPulseEvent (no idea)
  case 271: // NtRaiseException (ehrm... noise?)
  case 168: // NtMapViewOfSection (not so useful, could end up tainting too much data on dereference)
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

      /* TODO: uncomment to allow syscalls to interrupt encoding function calls
      if(current_event->kind == EventKind::encoding){
          current_event->discard = true;
      }

       events.closeEvent(thread, *current_event);
       */
    }

    cout << "SYSENTER " << sc.callno << " " << sc.name << endl;
    auto new_event = make_shared<Event>();
    new_event->kind = EventKind::syscall;
    new_event->entrypoint = static_cast<uint32_t>(sc.callno);
    new_event->started = call.start;
    new_event->label = next_available_label++;

    events.put_event(thread, new_event);

    // Read syscall parameters from argument stack (win7x86 only)

    uint64_t arg_start_pa = panda_virt_to_phys(cpu, arg_start);
    if(arg_start_pa == static_cast<uint64_t>(-1)){
        cout << "ERROR panda_virt_to_phys errored while translating " << arg_start_pa << endl;
        return;
    }

    unsigned const paramNumber = sc.paramNumber();
    for(unsigned i=0; i< paramNumber; i++){
        uint32_t buf = 0;
        const int res = panda_virtual_memory_read(cpu, arg_start + (i*4), reinterpret_cast<uint8_t*>(&buf), 4);
        if(res == -1){
            cerr << "ERROR unable to read syscall param" << endl;
        } else {
            cerr << "READ syscall param " << buf << endl;
            new_event->knownDataPointers.insert(buf, static_cast<int>(i));
        }
        new_event->argStack.push_back(buf);
    }

    if(current_tags.size()){
        cout << "current_tag " << current_tags[0] << endl;
        new_event->tags = current_tags;
    }

    /* Fine grained tainting (only taint arguments) */

    if(!only_taint_syscall_args || !taintEnabled()){
        return;
    }

    uint32_t taint_label = static_cast<uint32_t>(new_event->started);


    cout << "Tainting syscall args with lbl=" << taint_label << endl ;
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

    current_tags.push_back(event_label);

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

    auto thread = getFQThreadId(cpu);
    auto p_current_event = events.getEvent(thread);
    if(monitored_encoding_calls.count(entrypoint)){
        if(p_current_event){
            if(p_current_event->kind == EventKind::syscall){
                cerr << "encoding call during a syscall. This shouldn't happen. "
                     << entrypoint << " " << callid << " -- " << p_current_event->toString() << endl;
                return;
            }

            if(p_current_event->kind == EventKind::encoding){
                cerr << "encoding call during an encoding call. Ignoring "
                     << entrypoint << " " << callid << " -- " << p_current_event->toString() << endl;
                return;
            }
        }

        cout << "CALL " << entrypoint << " " << callid << endl;

        auto event = make_shared<Event>();
        event->kind = EventKind::encoding;
        event->entrypoint = entrypoint;
        event->thread = thread;
        event->started = callid;
        event->label = next_available_label++;

        events.put_event(thread, event);
    } else {
        if(!p_current_event && log_common_function_calls){
        //put the function in the map
            auto event = make_shared<Event>();
            event->kind = EventKind::commonfn;
            event->entrypoint = entrypoint;
            event->thread = thread;
            event->started = callid;
            event->label = next_available_label++;
            commonFunctions[callid] = event;
        }
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

    if(commonFunctions.count(callid)){
        auto& commonFn = commonFunctions[callid];
        if(commonFn->taintedReads > 16){
            finalize_event(cpu, commonFn);
            logEvent(*commonFn, outfp);
        } else if(!searches.empty()){
            //handle stringsearch
            std::vector<uint8_t> buff;
            bool found = false;
            buff.reserve(commonFn->memory.readset.size());
            for(const auto& read: commonFn->memory.readset){
                buff.push_back(read.second);
            }
            for(const SearchInfo& search : searches){
                auto it = std::search(buff.begin(), buff.end(),
                                      search.buffer.begin(), search.buffer.end());
                if(it != buff.end()){
                    found = true;
                    break;
                }
            }
            if(found){
                finalize_event(cpu, commonFn);
                logEvent(*commonFn, outfp);
            }
        }

        commonFunctions.erase(callid);
    }
}

void on_function_forced_return(CPUState *cpu, target_ulong entrypoint, uint64_t callid,
                               uint32_t skipped_frames){
    (void) cpu;
    (void) skipped_frames;
    (void) entrypoint;
    commonFunctions.erase(callid);
}

// ========================
// Memory access tracking
// ========================


int mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    (void) pc;
    if(debug_logs){
        uint8_t* data =  reinterpret_cast<uint8_t*>(buf);
        hwaddr physical_address = panda_virt_to_phys(cpu, addr);
        uint8_t printable0 = isprint(data[0]) ? data[0] : '_';
        uint8_t printable1 = size > 1 && isprint(data[1]) ? data[1] : '_';
        cerr << "WRITE " << rr_get_guest_instr_count()
             << " " << addr
             <<" (" << std::hex << physical_address << std::dec << ") "
             <<" size=" << size
             <<" byte=" << printable0 << printable1
             << endl;
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
            auto closest_datapointer = p_current_event->knownDataPointers.closest_known_datapointer(addr);

            if(only_taint_syscall_args){
                should_taint = false;
            } else if(use_candidate_pointers){
                should_taint = bool(closest_datapointer);
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
                    bool additive = false;
                    if(p_current_event->kind == EventKind::encoding){
                        additive = true;
                    }
                    writeLabelPA(physical_address+i, 1, p_current_event->getLabel(), additive);

                }
            }
        }
    } else {
        //common function
        auto callid = get_current_callid(cpu);
        if(commonFunctions.count(callid)){
            hwaddr physical_address = panda_virt_to_phys(cpu, addr);
            bool translation_error = physical_address == static_cast<hwaddr>(-1);
            if(translation_error) return 0;

            for(target_ulong i=0; i<size; i++){
                commonFunctions[callid]->memory.write(addr +i ,  data[i]);
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

    if(debug_logs){
        fprintf(stderr, "READ %d (%p) of %d bytes \n", addr, (void*)panda_virt_to_phys(cpu, addr), size);
    }

    auto thread = getFQThreadId(cpu);
    auto p_current_event = events.getEvent(thread);

    if(!isUserSpaceAddress(addr)){
        return 0;
    }

    //Update the known pointers list
    //this allows us to associate some data being read by a syscall with one of the syscall arguments
    if(p_current_event && p_current_event->kind == EventKind::syscall){
        auto closest_datapointer = p_current_event->knownDataPointers.closest_known_datapointer(addr);
        bool add_addr_to_candidate_pointers = bool(closest_datapointer);

        if(add_addr_to_candidate_pointers){
            uint32_t pointers_read = 0;
            uint32_t* ptrptr = reinterpret_cast<target_ulong*>(buf);

            // TODO not sure there's a point in reading more than a pointer at once
            while(size - pointers_read * sizeof(target_ulong) <= sizeof(target_ulong)){
                target_ulong ptr = ptrptr[pointers_read];
                p_current_event->knownDataPointers.insert(ptr, closest_datapointer->tag);
                pointers_read++;
            }
        }
    }

    if(p_current_event){
        for(target_ulong i=0; i< size; i++){
            p_current_event->memory.read(addr +i ,  data[i]);
        }
        readLabels(cpu, addr, size, [&p_current_event](uint32_t addri, uint32_t dep){
            p_current_event->memory.readdep(addri, dep);
        });
        return 0;
    }

    auto callid = get_current_callid(cpu);
    if(commonFunctions.count(callid)){
        hwaddr physical_address = panda_virt_to_phys(cpu, addr);
        bool translation_error = physical_address == static_cast<hwaddr>(-1);
        if(translation_error) return 0;

        for(target_ulong i=0; i<size; i++){
            commonFunctions[callid]->memory.read(addr +i ,  data[i]);

            uint32_t nlabels = tcgtaint_get_physical_memory_labels_count(physical_address + i);
            if(nlabels){
                commonFunctions[callid]->taintedReads++;
            }
        }

        readLabels(cpu, addr, size, [callid](uint32_t addri, uint32_t dep){
            commonFunctions[callid]->memory.readdep(addri, dep);
        });
    }

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


std::set<target_ulong> parse_addr_list(const std::string& addrs_s){
    const char* addrs = addrs_s.c_str();
    std::set<target_ulong> res;

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

void external_event_notif(CPUState *cpu, uint32_t eventid, uint32_t pointer, uint32_t len){
    (void) cpu;

    Event e;
    e.entrypoint = eventid;
    e.label = eventid;
    e.started = rr_get_guest_instr_count();
    e.ended = rr_get_guest_instr_count();
    e.kind = EventKind::notification;

    std::vector<uint8_t> buf(len);
    int res = panda_virtual_memory_read(cpu, pointer, &buf[0], static_cast<int>(len));
    if(res != -1){

        for(target_ulong i = 0; i < len; i++){
            e.memory.read(pointer+i, buf[i]);
        }

        readLabels(cpu, pointer, len, [&e](uint32_t addri, uint32_t dep){
             e.memory.readdep(addri, dep);
        });

        if (!no_callstack) {
          std::vector<target_ulong> current_callstack(10);
          int callstacksize =
              get_functions(current_callstack.data(),
                          static_cast<int>(current_callstack.size()), cpu);
          current_callstack.resize(callstacksize);
          e.callstack = std::move(current_callstack);
        }

    }
    //logging
    logEvent(e, outfp);
}


void loadConfigFile(const std::string& filename){
    std::ifstream cfgfile(filename);
    if(!cfgfile.is_open())
        throw std::invalid_argument("couldn't open config");
    auto configjson = nlohmann::json::parse(cfgfile);

    dont_enable_taint = configjson.value("notaint", false);
    target_taint_at = configjson.value("taintat",0UL);
    target_end_count = configjson.value("endat",0UL);
    only_taint_syscall_args = configjson.value("only_syscall_args", false);
    use_candidate_pointers = only_taint_syscall_args;

    if(configjson.count("asids")){
        std::vector<Asid> asids = configjson.at("asids");
        for (const Asid i: asids)
            monitored_processes.insert(i);
    } else {
        automatically_add_processes = true;
    }

    disable_taint_on_other_processes = configjson.value("no_taint_other", false);
    no_callstack = configjson.value("no_callstack", false);
    extevents_as_primary = configjson.value("extevents", false);
    no_syscalls = configjson.value("no_syscalls", false);

    if(configjson.count("encfns")){
        auto& encfns = configjson.at("encfns");
        if(encfns.is_string()){
            monitored_encoding_calls = parse_addr_list(encfns.get<string>());
        } else if (encfns.is_array()) {
            std::vector<Address> enc_calls = encfns;
            for(const Address a: enc_calls){
                monitored_encoding_calls.insert(a);
            }
        }
    }

    set_taint_dereference = configjson.value("taint_dereference", false);
    log_common_function_calls = configjson.value("log_common_fns", true);
}

std::string remove_extension(const std::string& filename) {
    size_t lastdot = filename.find_last_of(".");
    if (lastdot == std::string::npos) return filename;
    return filename.substr(0, lastdot);
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
    PPP_REG_CB("sysevent", on_sysevent_notif, external_event_notif);

    panda_arg_list *args = panda_get_args("systaint");
    if (args == NULL)
        return false;

    const char* cfg_file = panda_parse_string_req(args, "cfg", "Configuration file");
    const char* search = panda_parse_string_opt(args, "search", nullptr, "List of files whose contents to search in memory");

    if(search){
        SearchManager sm(32,4);
        sm.readFileList(search);
        searches = sm.searches;
        if(searches.empty()){
            cerr << "couldnt load any string to search" << endl;
            return false;
        }
    }

    loadConfigFile(cfg_file);

    if(use_candidate_pointers){
        std::cout << "Using candidate pointers" << std::endl;
    }

    cout << "no_taint " << dont_enable_taint << endl;
    cout << "no_taint_other " << disable_taint_on_other_processes << endl;
    cout << "no_callstack " << no_callstack << endl;

    if(!no_callstack){
        panda_require("callstack_instr");
        assert(init_callstack_instr_api());
        PPP_REG_CB("callstack_instr", on_call2, on_function_call);
        PPP_REG_CB("callstack_instr", on_ret2, on_function_return);
        PPP_REG_CB("callstack_instr", on_forcedret, on_function_forced_return);
    }

    if(no_syscalls){
        extevents_as_primary = true;
    }

    std::string outfilename = remove_extension(cfg_file);
    outfilename.append(".data");

    outfp = fopen(outfilename.data(), "w");
    if(!outfp){
        perror("unable to open output file");
        exit(-1);
    }

    cout << "BUILD" << __DATE__ << endl;
    cout << "CONFIG" << endl;
    std::ifstream f(cfg_file);
    if (f.is_open())
        std::cout << f.rdbuf();
    cout << endl;

    for(const auto&i : monitored_encoding_calls){
        cout << "tracking encfn " << i << endl;
    }

    for(const auto&i : monitored_processes){
        cout << "tracking process " << i << endl;
    }

    //TODO now probably useless
    panda_do_flush_tb();
    panda_enable_precise_pc();
    tcgtaint_set_taint_dereference(set_taint_dereference);

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

    if(!events.curr_events.empty()){
        cout << "UNTERMINATED " << endl;

        for(const auto& thread_event : events.curr_events){
            //const auto& t = thread_event.first;
            const auto& evs = thread_event.second;

            for(const auto& e : evs){
                std::cout << e->toString() << std::endl;
                logEvent(*e, outfp);
            }
        }

    }

    //printOutDeps();

    if(outfp){
        fclose(outfp);
    }

    #endif
}

