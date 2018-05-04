/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <cstdio>
#include <cstdlib>
#include <ctype.h>
#include <math.h>
#include <map>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <vector>
#include <set>
#include <json.hpp>
#include "base64.hpp"
#include "searchmanager.h"

using json = nlohmann::json;

#include "panda/plugin.h"

extern "C" {
#include "stringsearch2.h"
}

#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"
using namespace std;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

// Silly: since we use these as map values, they have to be
// copy constructible. Plain arrays aren't, but structs containing
// arrays are. So we make these goofy wrappers.
struct match_strings {
    int val[MAX_STRINGS];
};
struct string_pos {
    uint32_t val[MAX_STRINGS];
};
struct fullstack {
    int n;
    target_ulong callers[MAX_CALLERS];
    target_ulong pc;
    target_ulong asid;
};

struct SearchStatus {
    target_ulong bytesMatched = 0;
//    uint64_t commoncallerID = 0;
//    std::set<uint64_t> callIDs;
    uint64_t started = 0;
//    uint64_t ended = 0;
//    uint64_t asid = 0;
//    uint64_t pc = 0;
//    uint64_t id = 0;
};

struct MatchInfo {
    uint64_t started = 0;
    uint64_t ended = 0;
    uint64_t asid = 0;
    uint64_t pc = 0;
    uint64_t id = 0;
    bool is_write = 0;
    uint32_t last_addr = 0;
    uint32_t len = 0;
    std::vector<uint8_t> context;
    bool in_kernel = 0;
};

struct ProgPointStatus {
  uint64_t last_touched = 0;
  std::vector<SearchStatus> searchStatus;
};
using SearchStatusMap = std::map<prog_point, ProgPointStatus>;

static SearchStatusMap read_text_tracker;
static SearchStatusMap write_text_tracker;
static int n_callers = 16;
static std::vector<SearchInfo> searches;
static std::ofstream outfile;
static uint64_t target_end_count = 0;
static uint64_t target_start_count = 0;
static bool enabled = false;
static size_t CHUNK_LEN = 8;
static size_t NCHUNKS = 10;
static bool include_kernel_addrs = false;

void logSearchStatus(const MatchInfo& match, const SearchInfo& si, const std::vector<CallstackStackEntry>& callstack){
    json ret;
    ret["start"] = match.started;
    ret["end"] = match.ended;
    ret["asid"] = match.asid;
    ret["pc"] = match.pc;
    ret["name"] = si.name;
    auto callstackJson = json::array();
    auto callstackIDs = json::array();
    for(const auto& cs : callstack){
        callstackJson.push_back(cs.function);
        callstackIDs.push_back(cs.call_id);
    }
    ret["callstack_ids"] = callstackIDs;
    ret["callstack_fns"] = callstackJson;
    ret["kind"] = match.is_write? "write" : "read";
    ret["last_addr"] = match.last_addr;
    ret["len"] = match.len;
    if(match.context.size()){
        ret["context"] = base64_encode(match.context.data(), match.context.size());
    }
    ret["in_kernel"] = match.in_kernel;
    outfile <<  ret.dump() << std::endl;
}

bool isUserSpaceAddress(uint64_t virt_addr){
    const uint64_t MMUserProbeAddress = 0x7fff0000; // Start of kernel memory
    return virt_addr < MMUserProbeAddress;
}

int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf, bool is_write,
                       SearchStatusMap &text_tracker) {
    if(!isUserSpaceAddress(addr) && !include_kernel_addrs){
        return 1;
    }

    size_t nsearches = searches.size();

    prog_point p = {0,0,0};
    get_prog_point(env, &p);

    std::vector<SearchStatus> &sp = text_tracker[p].searchStatus;
    if(sp.size() == 0){
        sp.resize(nsearches);
    }

    text_tracker[p].last_touched = rr_get_guest_instr_count();

    for (unsigned int buf_idx = 0; buf_idx < size; buf_idx++) {
        uint8_t val = ((uint8_t *)buf)[buf_idx];

        for(size_t search_id = 0; search_id < nsearches; search_id++) {
            const auto& search = searches[search_id];
            auto& search_status = sp[search_id];

            if (static_cast<uint8_t>(search.buffer[search_status.bytesMatched]) == val){
                search_status.bytesMatched++;
                //search_status.callIDs.insert(get_current_callid(env));
                //if(search_status.bytesMatched > 1){
                //    cout << search_status.bytesMatched << endl;
                //}
                if(search_status.bytesMatched == 1){
                    search_status.started = rr_get_guest_instr_count();
                }
            } else if(static_cast<uint8_t>(search.buffer[0]) == val) {
                search_status.bytesMatched = 1;
                search_status.started = rr_get_guest_instr_count();
            } else {
                search_status.bytesMatched = 0;
                search_status.started = 0;
                continue;
            }

            if (search_status.bytesMatched == search.buffer.length()) {
                // Victory!

                MatchInfo match;

                match.is_write = is_write;
                match.started = search_status.started;
                match.ended = rr_get_guest_instr_count();
                match.asid = p.cr3;
                match.pc = p.pc;
                match.id = search_id;
                match.last_addr = addr;
                match.len = search_status.bytesMatched;
                match.in_kernel = panda_in_kernel(env);

                const char* is_write_str = is_write ? "WRITE" : "READ";
                printf("%s Match of str %s at: instr_count=%lu :  " TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx " %c \n",
                       is_write_str, search.name.c_str(), rr_get_guest_instr_count(),
                       p.caller, p.pc, p.cr3, match.in_kernel? 'K' : 'U');

                if(search.contextbytes){
                    target_ulong startAddr = addr - search_status.bytesMatched - search.contextbytes;
                    target_ulong readsize = (addr - startAddr) + search.contextbytes;
                    match.context.resize(readsize);
                    int res = panda_virtual_memory_read(env, startAddr, match.context.data(), (int)readsize);
                    if(res == -1){match.context.resize(0);}
                }

                std::vector<CallstackStackEntry> entries(n_callers);
                int n_entries = get_call_entries(entries.data(), static_cast<int>(entries.size()), env);
                entries.resize(n_entries);

                logSearchStatus(match, search, entries);
            }
        }
    }
 
    return 1;
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, false, read_text_tracker);
}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, true, write_text_tracker);
}

void cleanupMap(uint64_t current_instr, SearchStatusMap& ssm){
    for (auto it = ssm.cbegin(); it != ssm.cend();){
        if (current_instr - it->second.last_touched > 500000000){
            it = ssm.erase(it);
        } else {
            ++it;
        }
    }
}

void late_init(){
    cout << "Enabling" << std::endl;
    panda_do_flush_tb();
    panda_enable_memcb();
    panda_enable_precise_pc();
    panda_require("callstack_instr");
    assert(init_callstack_instr_api());
    enabled = true;
}

int stringsearch2_after_block_callback(CPUState *cpu, TranslationBlock *tb){
    static uint64_t last_cleanup = 0;
    (void) tb;

    auto instr_count = rr_get_guest_instr_count();

    if(!enabled && instr_count > target_start_count){
        late_init();
    }

    if(target_end_count && instr_count > target_end_count){
        rr_end_replay_requested = 1;
    }

    if(enabled && instr_count - last_cleanup > 1000000000){
        cout << "Cleaning up" << std::endl;
        cleanupMap(instr_count, read_text_tracker);
        cleanupMap(instr_count, write_text_tracker);
        last_cleanup = instr_count;
    }


    return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    panda_arg_list *args = panda_get_args("stringsearch");
    target_end_count = panda_parse_uint64_opt(args, "endat", 0, "instruction count when to end the replay");
    target_start_count = panda_parse_uint64_opt(args, "startat", 0, "instruction count when to start the replay");
    const char *filelist_file = panda_parse_string_req(args, "filelist", "filename of the list of filenames containing the strings to search");
    CHUNK_LEN = panda_parse_uint64_opt(args, "chunklen", 8, "length of each chunk");
    NCHUNKS = panda_parse_uint64_opt(args, "nchunks", 10, "number of chunks per search");
    include_kernel_addrs = panda_parse_bool(args, "include_kernel_addrs");
    n_callers = panda_parse_uint32_opt(args, "callers", 32, "depth of callstack for matches");
    if (n_callers > MAX_CALLERS) n_callers = MAX_CALLERS;

    SearchManager sm(CHUNK_LEN, NCHUNKS);
    sm.readFileList(filelist_file);
    searches = sm.searches;

    assert(searches.size());
    cout << "Added a total of " << searches.size() << " chunks" << std::endl;

    std::string outfilename(filelist_file);
    outfilename.append(".result");
    outfilename.append(std::to_string(target_start_count));
    outfilename.append(".json");

    outfile.open(outfilename, std::ofstream::out | std::ofstream::trunc);
    if(!outfile.is_open()){
        fprintf(stderr, "Unable to open output file");
    }

    pcb.virt_mem_before_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);
    pcb.virt_mem_after_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);
    pcb.before_block_exec = stringsearch2_after_block_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) {
}
