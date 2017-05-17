extern "C" {
#include "panda/plog.h"
}

#include "logging.hpp"
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <cstdio>

using namespace std;

void logEncFnCall(uint64_t callid, uint64_t entrypoint, CallMemAccessTracker& cmt, FILE* filepointer){

    Panda__EncFnCall encfncall = PANDA__ENC_FN_CALL__INIT;
    encfncall.callid =callid;
    encfncall.entrypoint = entrypoint;
    encfncall.n_reads = cmt.readset.size();

    Panda__EncFnRead *reads = new Panda__EncFnRead[encfncall.n_reads];
    Panda__EncFnRead **readPtrs = new Panda__EncFnRead*[encfncall.n_reads];

    //Turn depsets to arrays, so we can pass them to protobuf directly
    std::unordered_map<uint32_t, std::vector<uint32_t>> depsetAry;
    for(const auto& addr_deps : cmt.readsetDeps){
        auto& depary = depsetAry[addr_deps.first];
        for(const auto& dep : addr_deps.second){
            depary.push_back(dep);
        }
    }

    int i = 0;
    for(const auto& read_value :cmt.readset){
        const auto& deps = cmt.readsetDeps[read_value.first];
        reads[i] = PANDA__ENC_FN_READ__INIT;
        reads[i].n_dependencies = deps.size();
        reads[i].dependencies = &depsetAry[read_value.first][0];
        reads[i].value = read_value.second;
        readPtrs[i] = &reads[i];
        i++;
    }

    encfncall.reads = readPtrs;

    if(filepointer == 0 && pandalog){
        // Use pandalog
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.encfncall = &encfncall;
        pandalog_write_entry(&ple);

    } else {

        // Write to filepointer, prepended by the buffer's size
        uint64_t buffer_size = panda__enc_fn_call__get_packed_size(&encfncall);
        printf("buffer size %ld\n", buffer_size);
        uint8_t* buffer = new uint8_t[buffer_size+1];

        printf("ENCODING \n");
        panda__enc_fn_call__pack(&encfncall, buffer);
        printf("ENCODED \n");
        fwrite(&buffer_size, sizeof(buffer_size), 1, filepointer);
        fwrite(buffer, buffer_size, 1, filepointer);

        delete[] buffer;
    }

    delete[] reads;
    delete[] readPtrs;
}
