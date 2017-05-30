#include "panda/plugin.h"
#include "syscall_listener.hpp"
#include <set>
#include <boost/regex.hpp>
#include <fstream>
#include <iostream>

using boost::optional;

// parsed syscall definitions
static std::vector<Syscall> syscalls;

//tracked asid
extern uint32_t tracked_asid;

optional<Syscall> parsePrototype(const std::string& prototype){
    static boost::regex syscallRegex(R"((\d+)\s+(\w+)\s+(\w+)\s*\((.*)\);)");
    static boost::regex argsRegex(R"(\s?([^,]+))");

    boost::smatch syscallMatches;

    bool matched = boost::regex_match(prototype, syscallMatches, syscallRegex);
    if(!matched) return {};

    Syscall s;
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

// A SyscallPCpoint is added when a sysenter is translated, so that we can then recognize it when the sysenter actually happens
static std::set<std::pair <target_ulong, target_ulong>> syscallPCpoints;

/* When we execute an instruction (for which translate_callback returned true),
we check if it was the Sysenter we saw before */
int exec_callback(CPUState *cpu, target_ulong pc) {

#ifdef TARGET_I386
    auto current_asid = panda_current_asid(cpu);

    if (!syscallPCpoints.count(std::make_pair(pc,current_asid))){
        return 0;
    }

    CPUArchState *env = (CPUArchState*)cpu->env_ptr;

    // Retrieve the syscall definition or return
    // (there are currently several nondefined syscalls which we ignore)
    uint32_t syscall_no = env->regs[R_EAX];

    if(syscall_no >= syscalls.size()){
        std::cout << "Sysenter, no: " << syscall_no << "ignored" << std::endl ;
        return 0;
    }

    onSysEnter(cpu, pc, syscalls[syscall_no]);

#endif
    return 0;
}

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

