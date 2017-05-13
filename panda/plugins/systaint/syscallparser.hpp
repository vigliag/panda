#pragma once

#include <string>
#include <vector>
#include <boost/optional.hpp>

struct Syscall {
    int callno = -1;
    std::string name;
    std::string retval;
    std::vector<std::string> argDefs;
};

boost::optional<Syscall> parsePrototype(const std::string& prototype);