#include "panda/plugin.h" //include plugin api we are implementing
#include "taint2/taint2.h" //include taint2 module we'll use
#include "callstack_instr/callstack_instr.h"

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

#define HYPERCALL_SYSCALL_ENTER 1
#define HYPERCALL_SYSCALL_EXIT 2
#define SYSTAINT_MAGIC 0xffaaffcc

#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <map>
#include <set>
#include <unordered_set>
#include <stdio.h>
#include <cstdint>

using namespace std;

#include "syscallparser.hpp"
#include "callmemaccesstracker.hpp"
#include "logging.hpp"

/* Data structures */

// parsed syscall definitions
static std::vector<Syscall> syscalls;

/** Parses syscall definitions, called on plugin init */
void parseSyscallDefs(const std::string& prototypesFilename){
    std::ifstream infile(prototypesFilename);
    std::string line;

    while (std::getline(infile, line))
    {
        //cout << "parsing " << line << endl;
        auto parsedSyscall = parsePrototype(line);
        if(parsedSyscall){
            syscalls.push_back(*parsedSyscall);
        }
    }
}

// Dependency tree we are going to build
using dependencySet = std::unordered_set<uint32_t>;
static std::map<uint32_t, dependencySet> eventDependencies;


#ifdef TARGET_I386

uint32_t current_syscall = 0;
static uint32_t current_event = 0;
static uint32_t tracked_asid = 0;
static uint32_t tracked_encoding_fn = 0;
static bool no_llvm = false;
static const char* outfile = nullptr;
static FILE* outfp = nullptr;
CallMemAccessTracker current_event_memtracker;

// counters have an idea of how many read and writes we are talking about
static int n_mem_writes_to_taint = 0;
static int n_mem_reads_to_query = 0;
#endif


#ifdef TARGET_I386

/* On windows, checks if a virtual address is in user-space */
bool isUserSpaceAddress(uint64_t virt_addr){
    const uint64_t MMUserProbeAddress = 0x7fff0000; // Start of kernel memory
    return virt_addr < MMUserProbeAddress;
}

/* Used as a callback to add new_label as a dependency to this_label
   uses global data structures */
int eventDependencyAdder(uint32_t dependency, void *current_event_){
    uint32_t current_event = *(uint32_t*) current_event_;

    if(dependency != current_event){
        if(eventDependencies[current_event].count(dependency) == 0){
            printf("adding dependency %u -> %u \n", dependency, current_event);
            eventDependencies[current_event].insert(dependency);
        }
    }

    return 0;
}

int addEventDeps(CPUState* cpu, target_ulong addr, target_ulong size, uint32_t dependent){
    if(!taint2_enabled()) return 0;

    uint64_t abs_addr = panda_virt_to_phys(cpu, addr);
    if(abs_addr == static_cast<uint64_t>(-1)){
        cerr << "panda_virt_to_phys " << addr << " errored" << endl;
        return 0;
    }

    cout << "reading taint " << addr << "[" << size << "], adding dep to " << dependent << endl;
    for(uint64_t i=0; i< size; i++){
        taint2_labelset_ram_iter(abs_addr + i, eventDependencyAdder, &dependent);
    }

    return 1;
}


// A SyscallPCpoint is added when a sysenter is translated, so that we can then recognize it when the sysenter actually happens
static std::set<std::pair <target_ulong, target_ulong>> syscallPCpoints;


/* When an instruction is being translated, check if it's a sysenter, if it is
   add the target pc to syscallPCpoints. This code is copied from syscall2 */
bool translate_callback(CPUState *cpu, target_ulong pc) {
#ifdef TARGET_I386
    if(tracked_asid != panda_current_asid(cpu))
        return false;

    unsigned char buf[2] = {};
    panda_virtual_memory_rw(cpu, pc, buf, 2, 0);
    // Check if the instruction is syscall (0F 05)
    if (buf[0]== 0x0F && buf[1] == 0x05) {
        syscallPCpoints.insert(std::make_pair(pc, panda_current_asid(cpu)));
        return true;
    }
    // Check if the instruction is int 0x80 (CD 80)
    else if (buf[0]== 0xCD && buf[1] == 0x80) {
        syscallPCpoints.insert(std::make_pair(pc, panda_current_asid(cpu)));
        return true;
    }
    // Check if the instruction is sysenter (0F 34)
    else if (buf[0]== 0x0F && buf[1] == 0x34) {
        syscallPCpoints.insert(std::make_pair(pc, panda_current_asid(cpu)));
        return true;
    }
    else {
        return false;
    }
#endif
return false;
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
    
    uint32_t taint_label = current_event != 0 ? current_event : sc.callno;

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
    cout << "Reading taint from " << arg_start << " to " << arg_start + arg_len << endl;
    addEventDeps(cpu, arg_start, arg_len, taint_label);
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


/* When we execute an instruction (for which translate_callback returned true),
we check if it was the Sysenter we saw before */
int exec_callback(CPUState *cpu, target_ulong pc) {
    auto current_asid = panda_current_asid(cpu);

    if (!syscallPCpoints.count(std::make_pair(pc,current_asid))){
        return 0;
    }

    CPUArchState *env = (CPUArchState*)cpu->env_ptr;

    // Retrieve the syscall definition or return
    // (there are currently several nondefined syscalls which we ignore)
    uint32_t syscall_no = env->regs[R_EAX];

    if(syscall_no >= syscalls.size()){
        cout << "Sysenter, no: " << syscall_no << "ignored" << endl ;
        return 0;
    }

    onSysEnter(cpu, pc, syscalls[syscall_no]);

    return 0;
}


#endif

void systaint_event_enter(CPUState *cpu, uint32_t event_label){

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

void hypercall_event_listener(CPUState *cpu){
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    
    if(env->regs[R_EAX] != SYSTAINT_MAGIC)
        return;

    //printf("HYPERCALL " TARGET_FMT_ld " " TARGET_FMT_ld " " TARGET_FMT_ld "\n",
    //     env->regs[R_EBX], env->regs[R_ECX], env->regs[R_EDX]);


    bool entering = env->regs[R_EBX] == HYPERCALL_SYSCALL_ENTER ? true : false;
    uint32_t cuckoo_event = env->regs[R_ECX];

    if(entering){
        printf("SYSCALL enter: %" PRIu32 " \n", cuckoo_event);
        systaint_event_enter(cpu, cuckoo_event);
    }

    if(!entering){
        printf("SYSCALL exit: %" PRIu32 " \n", cuckoo_event);
        systaint_event_exit(cpu, cuckoo_event);
    }
}

int guest_hypercall_callback(CPUState *cpu){
#ifdef TARGET_I386
    hypercall_event_listener(cpu);
#endif

#ifdef TARGET_ARM
    // TODO
#endif
    return 1;
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
            taint2_label_ram(write_pa, current_event);
        }
    }

    logSysFnCall(callid, entrypoint, current_call_memtracker, outfp);
    current_call_memtracker.clear();
    current_encoding_call_ = 0;
}


// ======================== 
// Memory access tracking 
// ========================

int readsetDependencyAdder(uint32_t dependency, void *memaddress_){
    uint32_t memaddress = *(uint32_t*) memaddress_;
    printf("adding dependency %u to %u \n", dependency, memaddress);
    current_call_memtracker.readdep(memaddress, dependency);
    return 0;
}

int addCurrentEncFnCallMemAddressDeps(CPUState* cpu, target_ulong addr, target_ulong size){
    if(!taint2_enabled()) return 0;

    uint64_t ptr = panda_virt_to_phys(cpu, addr);
    if(ptr == static_cast<uint64_t>(-1)){
        cerr << "panda_virt_to_phys " << addr << " errored" << endl;
        return 0;
    }

    for(uint64_t i=0; i< size; i++){
        uint32_t this_addr = addr + i;
        taint2_labelset_ram_iter(ptr + i, readsetDependencyAdder, &this_addr);
    }

    return 1;
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
        //cout << "WRITE-LABELING " << addr << " [" <<  size << " ] with " << current_event << endl;
        for(target_ulong i=0; i<size; i++){
            current_event_memtracker.write(addr+i, data[i]);

            /* Can't apply taint here, as it would be immediately cleared by the taint instrumentation right after
            if(taint2_enabled()){
                taint2_label_ram(addr_pa + i, current_event);
            }*/
        }
    }

    uint32_t curr_encoding_call = getCurrentEncodingCall(cpu);
    if(curr_encoding_call){
        cout << "CURRENT ENCODING FN WRITE " << curr_encoding_call << endl;

        for(target_ulong i=0; i<size; i++){
            current_call_memtracker.write(addr+i, data[i]);

            /* Can't apply taint here, as it would be immediately cleared by the taint instrumentation right after
            if(taint2_enabled())
                taint2_label_ram(addr_pa + i, curr_encoding_call);
            }*/
        }
    }
    
    return 0;
}


// TODO substitute me with taint-changed, should be faster (less queries)
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
        addEventDeps(cpu, addr, size, current_event);
    }

    // If there's an encoding call currently executing, track its reads to find dependecies
    // and save the data that it's being read
    uint32_t current_encoding_function = getCurrentEncodingCall(cpu);
    if(current_encoding_function && current_event){
        cerr << "WARNING, both current_encoding_function and current_event are set" << endl;
    }

    if(current_encoding_function){
        cout << "CURRENT ENCODING FN READ" << endl;

        addEventDeps(cpu, addr, size, current_encoding_function);

        for(uint64_t i=0; i< size; i++){
            current_call_memtracker.read(addr + i, data[i]);
        }

        addCurrentEncFnCallMemAddressDeps(cpu, addr, size);
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
    pcb.guest_hypercall = guest_hypercall_callback;
    panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb);

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

    panda_require("callstack_instr");
    assert(init_callstack_instr_api());

    string fname = "/Panda/panda_repo/panda/plugins/syscalls2/windows7_x86_prototypes.txt";
    parseSyscallDefs(fname);
    cout << "parsed " << syscalls.size() << " syscalls" << endl;

    PPP_REG_CB("callstack_instr", on_call2, on_call);
    PPP_REG_CB("callstack_instr", on_ret2, on_return);
    PPP_REG_CB("taint2", on_taint_change, on_taint_change);

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

    taintchanges = fopen("/tmp/taintchanges.log", "w");
    assert(taintchanges);

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

    printf("un_initing systaint, reads %d, writes %d",
        n_mem_reads_to_query, n_mem_writes_to_taint);
    printOutDeps();

    if(outfp){
        fclose(outfp);
    }

    #endif
}

