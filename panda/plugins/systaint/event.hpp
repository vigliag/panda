#pragma once

#include <map>
#include <set>
#include <cstdint>
#include <sstream>
#include <vector>
#include <boost/optional.hpp>

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
  external,
  notification,
  commonfn
};

/* TODO
auto cmp = [](int a, int b) { return ... };
set<int, decltype(cmp)> s(cmp);


*/

struct KnownDataPointer{
    target_ulong pointer;
    int tag; //allows tagging a pointer, eg: with the number of the syscall argument

    KnownDataPointer(target_ulong pointer, int tag) : pointer(pointer), tag(tag){}
};

class KnownDataPointerStorage {
    struct KnownDataPointerCmp {
        bool operator()(const KnownDataPointer&a, const KnownDataPointer&b) const{
            return a.pointer < b.pointer;
        }
    };

private:
    std::set<KnownDataPointer, KnownDataPointerCmp> knownDataPointers;

public:

    void insert(target_ulong pointer, int tag=-1){
        knownDataPointers.emplace(pointer, tag);
    }

    boost::optional<KnownDataPointer> closest_known_datapointer(target_ulong addr) const {
        KnownDataPointer query(addr, -1);
        auto it_after = knownDataPointers.upper_bound(query);

        if(it_after == knownDataPointers.begin()){
            //can happen if .begin() == .end(), or if there's no smaller pointer
            //puts("discard (no lower)");
            return boost::optional<KnownDataPointer>();
        }

        it_after--;

        auto closest_known_data_pointer = *it_after;
        if (addr - closest_known_data_pointer.pointer >= 0x1000){
            //discard as the first candidate pointer is too distant
            //puts("discard (too distant)");
            return boost::optional<KnownDataPointer>();
        }

        return boost::optional<KnownDataPointer>(closest_known_data_pointer);
    }
};

struct Event {
    CallMemAccessTracker memory;
    KnownDataPointerStorage knownDataPointers;

    uint64_t started = 0;
    uint64_t ended = 0;
    uint32_t ret_addr = 0;
    uint32_t entrypoint = 0;
    uint32_t label = 0;
    bool discard = false;

    std::vector<uint32_t> tags;
    std::vector<target_ulong> callstack;

    std::vector<uint32_t> argStack;

    FQThreadId thread;
    EventKind kind = EventKind::unknown;
    uint32_t parent = 0;
    uint32_t taintedWrites = 0;

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
        case EventKind::notification:
            res << "notification"; break;
        case EventKind::commonfn:
            res << "commonfn"; break;
        }
        res << "id " << getLabel() << " ep: " << entrypoint
            << " started " << started << " thread " << thread.second;
        return res.str();
    }

    uint32_t getLabel() const {
        if(label) return label;
        else return started;
    }
};
