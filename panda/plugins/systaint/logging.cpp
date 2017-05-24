extern "C" {
#include "panda/plog.h"
}

#include "logging.hpp"
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <cstdio>
#include <unordered_set>

using namespace std;

std::unordered_map<uint32_t, std::vector<uint32_t>>
setmap_to_vectormap(std::map<uint32_t, std::unordered_set<uint32_t>>& setmap){
    std::unordered_map<uint32_t, std::vector<uint32_t>> result;
    for(const auto& key_setv: setmap){
        auto& depary = result[key_setv.first];
        for(const auto& dep : key_setv.second){
            depary.push_back(dep);
        }
    }
    return result;
}

void logSysFnCall(uint64_t callid, uint64_t entrypoint, CallMemAccessTracker& cmt, FILE* filepointer){

    Panda__SysFnCall encfncall = PANDA__SYS_FN_CALL__INIT;
    encfncall.callid =callid;
    encfncall.entrypoint = entrypoint;
    encfncall.n_reads = cmt.readset.size();
    encfncall.n_writes = cmt.writeset.size();

    //Turn depsets to arrays, so we can pass them to protobuf directly
    std::unordered_map<uint32_t, std::vector<uint32_t>> depsetAry = setmap_to_vectormap(cmt.readsetDeps);

    //Create the array of pointers to reads
    Panda__SysMemoryLocation *reads = new Panda__SysMemoryLocation[encfncall.n_reads];
    Panda__SysMemoryLocation **readPtrs = new Panda__SysMemoryLocation*[encfncall.n_reads];

    int i = 0;
    for(const auto& addr_value :cmt.readset){
        const auto& deps = cmt.readsetDeps[addr_value.first];

        reads[i] = PANDA__SYS_MEMORY_LOCATION__INIT;
        reads[i].n_dependencies = deps.size();
        reads[i].dependencies = &(depsetAry[addr_value.first][0]);
        reads[i].value = addr_value.second;
        reads[i].address = addr_value.first;
        readPtrs[i] = &reads[i];
        i++;
    }
    encfncall.reads = readPtrs;

    // Same for writes
    Panda__SysMemoryLocation *writes = new Panda__SysMemoryLocation[encfncall.n_writes];
    Panda__SysMemoryLocation **writePtrs = new Panda__SysMemoryLocation*[encfncall.n_writes];
    i= 0;
    for(const auto& addr_value :cmt.writeset){
        writes[i] = PANDA__SYS_MEMORY_LOCATION__INIT;
        writes[i].n_dependencies = 0;
        writes[i].dependencies = nullptr;
        writes[i].value = addr_value.second;
        writes[i].address = addr_value.first;
        writePtrs[i] = &writes[i];
        i++;
    }
    encfncall.writes = writePtrs;

    // Write entry either to pandalog or to file
    if(filepointer == 0 && pandalog){
        // Use pandalog
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.encfncall = &encfncall;
        pandalog_write_entry(&ple);

    } else {

        // Write to filepointer, prepended by the buffer's size
        uint64_t buffer_size = panda__sys_fn_call__get_packed_size(&encfncall);
        printf("buffer size %ld\n", buffer_size);
        uint8_t* buffer = new uint8_t[buffer_size+1];

        printf("ENCODING \n");
        panda__sys_fn_call__pack(&encfncall, buffer);
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

    fprintf(stderr, "Logged %lu, %lu \n", callid, entrypoint);
}
