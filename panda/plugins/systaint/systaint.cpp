
#include "panda/plugin.h" //include plugin api we are implementing
#include "taint2/taint2.h" //include taint2 module we'll use

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
#include "taint2/taint2_ext.h"

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

using namespace std;
#include "syscallparser.hpp"

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
static std::map<uint32_t, dependencySet> dependencies;

// A SyscallPCpoint is added when a sysenter is translated, so that we can then recognize it when the sysenter actually happens
static std::set<std::pair <target_ulong, target_ulong>> syscallPCpoints;

#ifdef TARGET_I386
// we track a single syscall and process at a time
// tracked_syscall is the last syscall cuckoo notified us
static uint32_t tracked_syscall = 0;
static uint32_t tracked_asid = 0;

// counters have an idea of how many read and writes we are talking about
static int n_mem_writes_to_taint = 0;
static int n_mem_reads_to_query = 0;
#endif


#ifdef TARGET_I386

size_t paramSize(const Syscall& sc){
    return sc.argDefs.size() * 4;
}

/* On sysenter, it takes the PA of the parameters of the current syscall */
uint64_t getArgStartPA(CPUState *cpu){
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    cout << "converting " << env->regs[R_EDX] + 8 << " to physical" << endl;
    return panda_virt_to_phys(cpu, env->regs[R_EDX] + 8);
}

/* On windows, checks if a virtual address is in user-space */
bool isUserSpaceAddress(uint64_t virt_addr){
    const uint64_t MMUserProbeAddress = 0x7fff0000; // Start of kernel memory
    return virt_addr < MMUserProbeAddress;
}

/* Used as a callback to add new_label as a dependency to this_label
   uses global data structures */
int dependencyAdder(uint32_t new_label, void *this_label_){
    uint32_t this_label = *(uint32_t*) this_label_;
    dependencySet& depSet = dependencies[this_label];

    if (depSet.count(new_label) == 0){
        printf("adding dependency %d -> %d", new_label, this_label);
        depSet.insert(new_label);
    }
    return 0;
}

/* Syscall detection handling */

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
void onSysEnter(CPUState *cpu, target_ulong pc){
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    
    uint32_t syscall_no = env->regs[R_EAX];
    cout << "Sysenter, no: " << syscall_no << " ";

    // Retrieve the syscall definition or return
    // (there are currently several nondefined syscalls which we ignore)
    Syscall sc;
    if(syscall_no >= syscalls.size()){
        cout << endl;
        return;
    } else {
        sc = syscalls[syscall_no];
    }

    cout << sc.name << endl;
    
    //get id from the last call we've been notified from cuckoo
    uint32_t taint_label = tracked_syscall;

    //take size and location of syscall parameters
    uint64_t arg_start = getArgStartPA(cpu);
    if(arg_start == -1){
        cout << "ERROR panda_virt_to_phys errored" <<endl;
        return;
    }

    size_t arg_len = paramSize(sc);

    /* Taint should be enabled by the first interesting event.
    If it's not enabled, it means we haven't started tracking things yet */
    if(!taint2_enabled()){
        return;
    }

    /* Read taint for syscall args, the current event depends on the ones who
    tainted the arguments of the current syscall */
    cout << "Reading taint from " << arg_start << " to " << arg_start + arg_len;
    for(size_t i=0; i<arg_len; i++){
        uint64_t ptr = arg_start + i;
        taint2_labelset_ram_iter(ptr, dependencyAdder, &taint_label);
    }
    cout << "done" << endl;

    // TODO taint EAX on sysExit (not required on windows)

    /* We now clear the taint from these arguments, and taint them again with
    the label of the current event. We do this to taint the pointers, so that 
    anytime this syscall uses them to write to memory, the result is also 
    tainted */ 
    cout << "Re-tainting";
    for(size_t i=0; i<arg_len; i++){
        uint64_t ptr = arg_start + i;
        taint2_delete_ram(ptr);
        taint2_label_ram(ptr, taint_label);
    }
    cout << "done" << endl;
}

/* When we execute an instruction (for which translate_callback returned true),
we check if it was the Sysenter we saw before */
int exec_callback(CPUState *cpu, target_ulong pc) {
    auto current_asid = panda_current_asid(cpu);
    if (syscallPCpoints.end() != 
        syscallPCpoints.find(std::make_pair(pc,current_asid))){
        onSysEnter(cpu, pc);
    }
    return 0;
}
#endif

void i386_hypercall_callback(CPUState *cpu){
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    
    if(env->regs[R_EAX] != SYSTAINT_MAGIC) return;

    bool entering = env->regs[R_EBX] == HYPERCALL_SYSCALL_ENTER ? true : false;
    uint32_t syscall_id = env->regs[R_ECX];

    //printf("HYPERCALL " TARGET_FMT_ld " " TARGET_FMT_ld " " TARGET_FMT_ld "\n",
    //     env->regs[R_EBX], env->regs[R_ECX], env->regs[R_EDX]);

    target_ulong asid = panda_current_asid(ENV_GET_CPU(env));
    printf(TARGET_FMT_ld " ", asid);
    tracked_asid = asid; //TODO this should be made into a set

    if(entering){

        if (!taint2_enabled()) {
            printf ("enabling taint\n");
            taint2_enable_taint();    
        }

        if(!tracked_syscall){
            // we are entering a new, top-level syscall
            printf("SYSCALL enter: %" PRIu32 " \n", syscall_id);
            tracked_syscall = syscall_id;
        } else {
            // we are already in a syscall and we are detecting another
            printf("SYSCALL ignored  %" PRIu32 " \n", syscall_id);
        } 

    } else {
        
        if(tracked_syscall == syscall_id){
            printf("SYSCALL exit: %" PRIu32 " \n", syscall_id);
            tracked_syscall = 0;
        }
    }

    //target_ulong addr = panda_virt_to_phys(cpu, env->regs[R_EAX]);

}

int mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    //CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    
    if (!tracked_syscall || tracked_asid != panda_current_asid(cpu)){
        return 0;
    }

    n_mem_writes_to_taint++;
    
    //for(target_ulong i=0; i<size; i++){
    //    taint2_label_ram(addr + i, current_syscall);
    //}

    return 0;
}

// TODO substitute me with taint-changed, should be faster (less queries)
int mem_read_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size) {
    //CPUArchState *env = (CPUArchState*)cpu->env_ptr;

    if (!tracked_syscall
         || tracked_asid != panda_current_asid(cpu) 
         || !isUserSpaceAddress(addr)){
        return 0;
    }

    uint64_t ptr = panda_virt_to_phys(cpu, addr);
    if(ptr == -1){
        cout << "panda_virt_to_phys " << addr << " errored" << endl;
        return 0;
    }

    for(uint64_t i=0; i< size; i++){
        cout << "Reading deps of " << tracked_syscall << " from " << ptr + i << endl;
        taint2_labelset_ram_iter(ptr + i, dependencyAdder, &tracked_syscall);
        cout << " done" << endl;
    }

    n_mem_reads_to_query++;

    return 0;
}

#endif // TARGET_I386

int guest_hypercall_callback(CPUState *cpu){
#ifdef TARGET_I386
    i386_hypercall_callback(cpu);
#endif

#ifdef TARGET_ARM
    // TODO
#endif
    return 1;
}




void *plugin_self;

bool init_plugin(void *self) {
 
#ifdef TARGET_I386
    plugin_self = self;
    panda_cb pcb;
    pcb.guest_hypercall = guest_hypercall_callback;
    panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb);

    panda_enable_memcb();

    //pcb.virt_mem_after_write = mem_write_callback;
    //panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);
    pcb.virt_mem_before_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);
    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

    panda_require("taint2");
    assert(init_taint2_api());

    string fname = "/Panda/panda_repo/panda/plugins/syscalls2/windows7_x86_prototypes.txt";
    parseSyscallDefs(fname);
    cout << "parsed " << syscalls.size() << " syscalls" << endl;
    //panda_arg_list *args = panda_get_args("systaint");
    //panda_require("callstack_instr");
    //assert(init_callstack_instr_api());

#endif

    return true;
}


void printOutDeps(){
    for (auto& it : dependencies){
        uint32_t to = it.first;
        const dependencySet& depset = it.second;

        for (auto& from : depset){
            printf("DEPENDENCY %d %d \n", from, to);
        }
    }
}


void uninit_plugin(void *self) {
    #ifdef TARGET_I386
    printf("un_initing systaint, reads %d, writes %d",
        n_mem_reads_to_query, n_mem_writes_to_taint);
    printOutDeps();
    #endif
}
