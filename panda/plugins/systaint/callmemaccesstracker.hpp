#ifndef CALLMEMACCESSTRACKER_HPP
#define CALLMEMACCESSTRACKER_HPP

#include <map>
#include <unordered_set>
#include <cstdint>

class CallMemAccessTracker
{
public:
    std::map<uint32_t, uint8_t> writeset;
    std::map<uint32_t, uint8_t> readset;
    std::map<uint32_t, std::unordered_set<uint32_t>> readsetDeps;

    CallMemAccessTracker(){

    }

    void read(uint32_t addr, uint8_t data){
        if(writeset.count(addr)){
            readset[addr] = data;
        }
    }

    void readdep(uint32_t addr, uint32_t dependency){
        readsetDeps[addr].insert(dependency);
    }

    void write(uint32_t addr, uint8_t data){
        writeset[addr] = data;
    }

    void clear(){
        writeset.clear();
        readset.clear();
    }
};

#endif // CALLMEMACCESSTRACKER_HPP
