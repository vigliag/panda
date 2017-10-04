#include "panda/plugin.h"
#include "syscall_listener.hpp"
#include <set>
#include <boost/regex.hpp>
#include <fstream>
#include <iostream>
#include "introspection.hpp"

using boost::optional;


/* Syscall definitions */

// parsed syscall definitions
static std::vector<SyscallDef> syscalls;

optional<SyscallDef> parsePrototype(const std::string& prototype){
    static boost::regex syscallRegex(R"((\d+)\s+(\w+)\s+(\w+)\s*\((.*)\);)");
    static boost::regex argsRegex(R"(\s?([^,]+))");

    boost::smatch syscallMatches;

    bool matched = boost::regex_match(prototype, syscallMatches, syscallRegex);
    if(!matched) return {};

    SyscallDef s;
    s.callno = std::stoi(syscallMatches[1]);
    s.retval = syscallMatches[2].str();
    s.name = syscallMatches[3].str();

    std::string argsRaw = syscallMatches[4].str();

    boost::smatch argsMatches;
    while (boost::regex_search(argsRaw, argsMatches, argsRegex)) {
      s.argDefs.push_back(argsMatches[1].str());
      argsRaw = argsMatches.suffix();
    }

    return s;
}

/** Parses syscall definitions, called on plugin init */
void parseSyscallDefs(const std::string& prototypesFilename){
    std::ifstream infile(prototypesFilename);

    if(infile.fail()){
        std::string errorMsg = "unable to open " + prototypesFilename;
        throw std::runtime_error(errorMsg);
    }

    std::string line;

    while (std::getline(infile, line))
    {
        auto parsedSyscall = parsePrototype(line);
        if(parsedSyscall){
            syscalls.push_back(*parsedSyscall);
        }
    }

    std::cout << "parsed " << syscalls.size() << " syscalls" << std::endl;
}

/* Syscall tracking */

//active syscalls (per process,thread)
std::map<std::pair<uint32_t, uint32_t>, SysCall> active_syscalls;

//tracked asid
extern std::set<uint32_t> monitored_processes;

// A SyscallPCpoint is added when a sysenter is translated, so that we can then recognize it when the sysenter actually happens
static std::set<std::pair <target_ulong, target_ulong>> syscallPCpoints;

/* When we execute an instruction (for which translate_callback returned true),
we check if it was the Sysenter we saw before */
int exec_callback(CPUState *cpu, target_ulong pc) {

#ifdef TARGET_I386

    auto current_asid = panda_current_asid(cpu);

    if(!monitored_processes.count(current_asid))
        return 0;

    if (!syscallPCpoints.count(std::make_pair(pc,current_asid)))
        return 0;

    // Retrieve the syscall definition (ignore undefined syscalls)
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    uint32_t syscall_no = env->regs[R_EAX];

    if(syscall_no >= syscalls.size()){
        std::cout << "Sysenter, no: " << syscall_no << "ignored" << std::endl ;
        return 0;
    }
    auto syscallDef = syscalls[syscall_no];

    SysCall call;
    call.caller = pc;
    call.start = rr_get_guest_instr_count();
    call.syscall_no = syscall_no;

    target_ulong retaddr = 0;
    panda_virtual_memory_rw(cpu, env->regs[R_EDX], (uint8_t *) &retaddr, 4, false);
    call.return_addr = retaddr;

    active_syscalls[std::make_pair(current_asid, get_current_thread_id(cpu))] = call;
    onSysEnter(cpu, syscalls[syscall_no], call);

#endif
    return 0;
}

/* When an instruction is being translated, check if it's a sysenter, if it is
   add the target pc to syscallPCpoints. This code is copied from syscall2 */
bool translate_callback(CPUState *cpu, target_ulong pc) {
#ifdef TARGET_I386
    if(!monitored_processes.count(panda_current_asid(cpu)))
        return false;

    bool syscall_dectected = false;

    unsigned char buf[2] = {};
    panda_virtual_memory_rw(cpu, pc, buf, 2, 0);

    // Check if the instruction is syscall (0F 05)
    if (buf[0]== 0x0F && buf[1] == 0x05) {
        syscall_dectected = true;
    }
    // Check if the instruction is int 0x80 (CD 80)
    else if (buf[0]== 0xCD && buf[1] == 0x80) {
        syscall_dectected = false;
    }
    // Check if the instruction is sysenter (0F 34)
    else if (buf[0]== 0x0F && buf[1] == 0x34) {
        return true;
    }

    if(syscall_dectected){
        syscallPCpoints.insert(std::make_pair(pc, panda_current_asid(cpu)));
        return true;

    } else {
        return false;
    }

#endif
return false;
}

int returned_check_callback(CPUState *cpu, TranslationBlock* tb){
#ifdef TARGET_I386
    if(!monitored_processes.count(panda_current_asid(cpu)))
        return false;

    auto thread = std::make_pair(panda_current_asid(cpu), get_current_thread_id(cpu));

    // check if any of the internally tracked syscalls has returned
    // only one should be at its return point for any given basic block
    if (active_syscalls.count(thread)){
        auto& syscall = active_syscalls[thread];

        if(tb->pc == syscall.return_addr){
            onSysExit(cpu, syscalls[syscall.syscall_no], active_syscalls[thread]);
            active_syscalls.erase(thread);
        }
    }

#endif
    return false;
}

