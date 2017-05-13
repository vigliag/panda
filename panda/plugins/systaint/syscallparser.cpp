#include "syscallparser.hpp"
#include <boost/regex.hpp>
using boost::optional;


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
