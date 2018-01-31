#include "panda/cheaders.h"

#include "panda/plog-cc.hpp"

#include "logging.hpp"
#include <vector>
#include <unordered_map>
#include <cstdio>
#include <unordered_set>
#include <iostream>
#include <map>
#include <set>

#include "../fn_memlogger/EntropyCalculator.hpp"

/** Holds a synthetic description of a given buffer */
struct BufferInfo {
    target_ulong base = 0;
    target_ulong len = 0;
    float entropy = -1;
    std::vector<uint8_t> data;
    const std::set<uint32_t>* deps;

    std::string toString() const {
        std::stringstream ss;
        ss << reinterpret_cast<void*>(base) << "+" << len << ":" << entropy << ";";
        return ss.str();
    }
};


/* Computes a vector of BufferInfo from a map<address,data> (read/writeset) */
std::vector<BufferInfo> toBufferInfos(const std::map<target_ulong, uint8_t>& addrset,
                                      const std::map<uint32_t, std::set<uint32_t>>* depset = nullptr){
    std::vector<BufferInfo> res;
    BufferInfo current_buff;
    EntropyCalculator ec;

    for (const auto& addr_data : addrset) {
        const target_ulong& addr = addr_data.first;
        const uint8_t& data = addr_data.second;

        const auto* pdeps = (depset && depset->count(addr)) ? &depset->at(addr) : nullptr;


        const bool continuing = (addr == current_buff.base + current_buff.len) &&
                                ((pdeps == current_buff.deps) ||
                                    ((pdeps != nullptr && current_buff.deps != nullptr) && (*pdeps == *current_buff.deps))
                                 );

        if(continuing){
            // continue previous buffer
            current_buff.len++;
            current_buff.data.push_back(data);
            ec.add(data);

        } else {
            // start new BufferInfo

            if(current_buff.base){
                // finalize and save the old one first
                current_buff.entropy = ec.get();
                res.push_back(current_buff);
            }

            // init new buffer
            current_buff.data.clear();
            ec.reset();

            current_buff.base = addr;
            current_buff.len = 1;
            current_buff.data.push_back(data);
            current_buff.deps = pdeps;
            ec.add(data);
        }
    }

    // process last buffer (if any - ie addrset wasn't empty)
    if(current_buff.base){
        current_buff.entropy = ec.get();
        res.push_back(current_buff);
    }

    return res;
}


std::unordered_map<uint32_t, std::vector<uint32_t>>
setmap_to_vectormap(const std::map<uint32_t, std::set<uint32_t>>& setmap){
    std::unordered_map<uint32_t, std::vector<uint32_t>> result;
    for(const auto& key_setv: setmap){
        auto& depary = result[key_setv.first];
        for(const auto& dep : key_setv.second){
            depary.push_back(dep);
        }
    }
    return result;
}

void logEvent(const Event& event, FILE* filepointer){

    if(event.discard == true){
        return;
    }

    panda::SysFnCall *pbEvent = new panda::SysFnCall;

    pbEvent->set_started(event.started);
    pbEvent->set_entrypoint(event.entrypoint);
    pbEvent->set_ended(event.ended);
    pbEvent->set_kind(static_cast<uint32_t>(event.kind));
    pbEvent->set_parent(event.parent);
    pbEvent->set_pid(event.thread.first);
    pbEvent->set_thread(event.thread.second);
    pbEvent->set_label(event.getLabel());

    //Turn depsets to arrays, so we can pass them to protobuf directly
    std::unordered_map<uint32_t, std::vector<uint32_t>> depsetAry = setmap_to_vectormap(event.memory.readsetDeps);

    std::vector<BufferInfo> readBuffers = toBufferInfos(event.memory.readset, &event.memory.readsetDeps);
    std::vector<BufferInfo> writeBuffers = toBufferInfos(event.memory.writeset);

    const std::vector<uint32_t> &tags = event.tags;

    //Create the array of pointers to reads
    //panda::SysMemoryLocation *reads = new panda::SysMemoryLocation[readBuffers.size()];
    //panda::SysMemoryLocation **readPtrs = new panda::SysMemoryLocation*[readBuffers.size()];

    for(const auto& buffer : readBuffers){
        const auto& addr = buffer.base;

        panda::SysMemoryLocation *read = pbEvent->add_reads();

        for(const auto& dependency: depsetAry[addr]){
            read->add_dependencies(dependency);
        }

        read->set_value(buffer.data.data(), buffer.data.size());
        read->set_address(addr);

        std::optional<KnownDataPointer> closest_known_datapointer = event.knownDataPointers.closest_known_datapointer(addr);
        if(closest_known_datapointer){
            read->set_argno(closest_known_datapointer->tag);
        }else{
            read->set_argno(0);
        }
    }

    for(const auto& tag : tags){
        pbEvent->add_tags(tag);
    }

    for(const auto& argval : event.argStack){
        pbEvent->add_argstack(argval);
    }

    for(const auto& call: event.callstack){
        pbEvent->add_callstack(call);
    }

    for(const auto& buffer : writeBuffers){
        const auto& addr = buffer.base;

        panda::SysMemoryLocation *write = pbEvent->add_writes();

        write->set_value(buffer.data.data(), buffer.data.size());
        write->set_address(addr);
        write->set_argno(0);
    }

    // Write entry either to pandalog or to file
    if(filepointer == 0 && pandalog){
        // Use pandalog
        PandaLog p;

        std::unique_ptr<panda::LogEntry> ple(new panda::LogEntry);
        ple->set_allocated_encfncall(pbEvent);
        p.write_entry(std::move(ple));

    } else {
        assert(filepointer);

        std::string res = pbEvent->SerializeAsString();
        size_t buffer_size = res.size();

        fwrite(&buffer_size, sizeof(buffer_size), 1, filepointer);
        fwrite(res.data(), buffer_size, 1, filepointer);
        fflush(filepointer);

        delete pbEvent;
    }

    fprintf(stderr, "Logged %s \n", event.toString().c_str());
}
