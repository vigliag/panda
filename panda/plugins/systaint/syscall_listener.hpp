#ifndef SYSCALL_LISTENER_HPP
#define SYSCALL_LISTENER_HPP

#include <string>
#include <vector>
#include <boost/optional.hpp>

struct Syscall {
    int callno = -1;
    std::string name;
    std::string retval;
    std::vector<std::string> argDefs;

    std::size_t paramSize() const{
        return argDefs.size() * 4;
    }
};

boost::optional<Syscall> parsePrototype(const std::string& prototype);
void parseSyscallDefs(const std::string& prototypesFilename);
bool translate_callback(CPUState *cpu, target_ulong pc);
int exec_callback(CPUState *cpu, target_ulong pc);
void onSysEnter(CPUState *cpu, target_ulong pc, const Syscall& sc);

#endif // SYSCALL_LISTENER_HPP
