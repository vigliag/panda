#pragma once

#include <map>
#include <set>
#include <cstdint>
#include <sstream>
#include <vector>

class CallMemAccessTracker
{
public:
    std::map<uint32_t, uint8_t> writeset;
    std::map<uint32_t, uint8_t> readset;
    std::map<uint32_t, std::set<uint32_t>> readsetDeps;

    CallMemAccessTracker(){

    }

    void read(uint32_t addr, uint8_t data){
        if(writeset.count(addr) == 0 && readset.count(addr)==0){
            readset[addr] = data;
        }
    }

    void readdep(uint32_t addr, uint32_t dependency){
        if(writeset.count(addr) == 0){
            readsetDeps[addr].insert(dependency);
        }
    }

    void write(uint32_t addr, uint8_t data){
        writeset[addr] = data;
    }

    void clear(){
        writeset.clear();
        readset.clear();
    }
};

/**
 * FullyQualified Thread ID, made of asid, thread_id
 **/
using FQThreadId = std::pair<uint32_t, uint32_t>;

enum class EventKind {
  unknown=0,
  syscall,
  encoding,
  external
};

struct Event {
    CallMemAccessTracker memory;
    std::set<target_ulong> knownDataPointers;

    uint64_t started = 0;
    uint64_t ended = 0;
    uint32_t ret_addr = 0;
    uint32_t entrypoint = 0;
    uint32_t label = 0;

    std::vector<uint32_t> tags;
    std::vector<target_ulong> callstack;

    FQThreadId thread;
    EventKind kind = EventKind::unknown;
    uint32_t parent = 0;

    std::string toString() const {
        std::stringstream res;
        res << "Event: ";
        switch(kind){
        case EventKind::syscall:
            res << "syscall "; break;
        case EventKind::encoding:
            res << "encoding "; break;
        case EventKind::external:
            res << "external "; break;
        case EventKind::unknown:
            res << "unknown "; break;
        }
        res << "id " << getLabel() << " started " << started << " thread " << thread.second;
        return res.str();
    }

    uint32_t getLabel() const {
        if(label) return label;
        else return started;
    }

};
