#include "panda/cheaders.h"

extern "C" {
#include "panda/plog.h"
}

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

    Panda__SysFnCall pbEvent= PANDA__SYS_FN_CALL__INIT;
    pbEvent.started = event.started;
    pbEvent.entrypoint = event.entrypoint;
    pbEvent.ended = event.ended;
    pbEvent.kind = static_cast<uint32_t>(event.kind);
    pbEvent.parent = event.parent;
    pbEvent.pid = event.thread.first;
    pbEvent.thread = event.thread.second;

    //Turn depsets to arrays, so we can pass them to protobuf directly
    std::unordered_map<uint32_t, std::vector<uint32_t>> depsetAry = setmap_to_vectormap(event.memory.readsetDeps);

    std::vector<BufferInfo> readBuffers = toBufferInfos(event.memory.readset, &event.memory.readsetDeps);
    std::vector<BufferInfo> writeBuffers = toBufferInfos(event.memory.writeset);

    //std::vector<uint32_t> tags(event.tags.begin(), event.tags.end());
    const std::vector<uint32_t> &tags = event.tags;

    //Create the array of pointers to reads
    Panda__SysMemoryLocation *reads = new Panda__SysMemoryLocation[readBuffers.size()];
    Panda__SysMemoryLocation **readPtrs = new Panda__SysMemoryLocation*[readBuffers.size()];

    size_t i = 0;
    for(const auto& buffer : readBuffers){
        const auto& addr = buffer.base;

        reads[i] = PANDA__SYS_MEMORY_LOCATION__INIT;
        reads[i].n_dependencies = depsetAry[addr].size();
        reads[i].dependencies = &(depsetAry[addr][0]);

        ProtobufCBinaryData pcbd;
        pcbd.data = const_cast<uint8_t*>(buffer.data.data());
        pcbd.len = buffer.data.size();
        assert(pcbd.len == 0 || pcbd.data != nullptr);

        reads[i].value = pcbd;

        reads[i].address = buffer.base;
        readPtrs[i] = &reads[i];
        i++;
    }

    pbEvent.n_tags = tags.size();
    pbEvent.tags = const_cast<uint32_t*>(tags.data());

    pbEvent.n_reads = i;
    pbEvent.reads = readPtrs;

    // Same for writes
    Panda__SysMemoryLocation *writes = new Panda__SysMemoryLocation[writeBuffers.size()];
    Panda__SysMemoryLocation **writePtrs = new Panda__SysMemoryLocation*[writeBuffers.size()];

    i= 0;
    for(const auto& buffer : writeBuffers){
        writes[i] = PANDA__SYS_MEMORY_LOCATION__INIT;
        writes[i].n_dependencies = 0;
        writes[i].dependencies = nullptr;

        ProtobufCBinaryData pcbd;
        pcbd.data = const_cast<uint8_t*>(buffer.data.data());
        pcbd.len = buffer.data.size();
        assert(pcbd.len == 0 || pcbd.data != nullptr);

        writes[i].value = pcbd;
        writes[i].address = buffer.base;
        writePtrs[i] = &writes[i];

        i++;
    }
    pbEvent.n_writes = i;
    pbEvent.writes = writePtrs;

    // Write entry either to pandalog or to file
    if(filepointer == 0 && pandalog){
        // Use pandalog
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.encfncall = &pbEvent;
        pandalog_write_entry(&ple);

    } else {
        assert(filepointer);

        // Write to filepointer, prepended by the buffer's size
        uint64_t buffer_size = panda__sys_fn_call__get_packed_size(&pbEvent);
        uint8_t* buffer = new uint8_t[buffer_size+1];

        panda__sys_fn_call__pack(&pbEvent, buffer);

        fwrite(&buffer_size, sizeof(buffer_size), 1, filepointer);
        fwrite(buffer, buffer_size, 1, filepointer);
        fflush(filepointer);

        delete[] buffer;
    }

    delete[] reads;
    delete[] readPtrs;
    delete[] writes;
    delete[] writePtrs;

    fprintf(stderr, "Logged %s \n", event.toString().c_str());
}
