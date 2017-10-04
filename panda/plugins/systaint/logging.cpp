#include "panda/cheaders.h"

extern "C" {
#include "panda/plog.h"
}

#include "logging.hpp"
#include <vector>
#include <unordered_map>
#include <cstdio>
#include <unordered_set>

using namespace std;

std::unordered_map<uint32_t, std::vector<uint32_t>>
setmap_to_vectormap(const std::map<uint32_t, std::unordered_set<uint32_t>>& setmap){
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
    pbEvent.n_reads = event.memory.readset.size();
    pbEvent.n_writes = event.memory.writeset.size();

    //Turn depsets to arrays, so we can pass them to protobuf directly
    std::unordered_map<uint32_t, std::vector<uint32_t>> depsetAry = setmap_to_vectormap(event.memory.readsetDeps);

    //Create the array of pointers to reads
    Panda__SysMemoryLocation *reads = new Panda__SysMemoryLocation[pbEvent.n_reads];
    Panda__SysMemoryLocation **readPtrs = new Panda__SysMemoryLocation*[pbEvent.n_reads];

    int i = 0;
    for(const auto& addr_value : event.memory.readset){

        reads[i] = PANDA__SYS_MEMORY_LOCATION__INIT;
        reads[i].n_dependencies = depsetAry[addr_value.first].size();
        reads[i].dependencies = &(depsetAry[addr_value.first][0]);
        reads[i].value = addr_value.second;
        reads[i].address = addr_value.first;
        readPtrs[i] = &reads[i];
        i++;
    }
    pbEvent.reads = readPtrs;

    // Same for writes
    Panda__SysMemoryLocation *writes = new Panda__SysMemoryLocation[pbEvent.n_writes];
    Panda__SysMemoryLocation **writePtrs = new Panda__SysMemoryLocation*[pbEvent.n_writes];
    i= 0;
    for(const auto& addr_value : event.memory.writeset){
        writes[i] = PANDA__SYS_MEMORY_LOCATION__INIT;
        writes[i].n_dependencies = 0;
        writes[i].dependencies = nullptr;
        writes[i].value = addr_value.second;
        writes[i].address = addr_value.first;
        writePtrs[i] = &writes[i];
        i++;
    }
    pbEvent.writes = writePtrs;

    // Write entry either to pandalog or to file
    if(filepointer == 0 && pandalog){
        // Use pandalog
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.encfncall = &pbEvent;
        pandalog_write_entry(&ple);

    } else {

        // Write to filepointer, prepended by the buffer's size
        uint64_t buffer_size = panda__sys_fn_call__get_packed_size(&pbEvent);
        printf("buffer size %ld\n", buffer_size);
        uint8_t* buffer = new uint8_t[buffer_size+1];

        printf("ENCODING \n");
        panda__sys_fn_call__pack(&pbEvent, buffer);
        printf("ENCODED \n");

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
