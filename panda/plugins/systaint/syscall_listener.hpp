#ifndef SYSCALL_LISTENER_HPP
#define SYSCALL_LISTENER_HPP

#include <string>
#include <vector>
#include <boost/optional.hpp>

struct SyscallDef {
    int callno = -1;
    std::string name;
    std::string retval;
    std::vector<std::string> argDefs;

    std::size_t paramSize() const{
        return argDefs.size() * 4;
    }
};

struct SysCall {
    uint32_t syscall_no = 0;
    uint32_t caller = 0;
    uint64_t start = 0;
    uint64_t end = 0;
    uint32_t return_addr = 0;
};

boost::optional<SyscallDef> parsePrototype(const std::string& prototype);
void parseSyscallDefs(const std::string& prototypesFilename);
bool translate_callback(CPUState *cpu, target_ulong pc);
int exec_callback(CPUState *cpu, target_ulong pc);

void onSysEnter(CPUState *cpu, const SyscallDef& sc, const SysCall call);
void onSysExit(CPUState *cpu, const SyscallDef& sc, const SysCall call);

int returned_check_callback(CPUState *cpu, TranslationBlock* tb);


#endif // SYSCALL_LISTENER_HPP
