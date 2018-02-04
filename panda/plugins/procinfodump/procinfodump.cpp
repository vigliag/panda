/**
 * This plugin listens for hypercalls and emits SYSENTER/SYSEXIT events
 */

#include "panda/plugin.h"

#include <algorithm>
#include <fstream>
#include <functional>
#include <iostream>
#include <json.hpp>
#include <map>
#include <queue>
#include <sstream>
#include <stdint.h>
#include <string>

#include <pybind11/embed.h> // everything needed for embedding
#include <pybind11/stl.h>

#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

extern ram_addr_t ram_size;

namespace py = pybind11;
const int READONLY = false;

extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

struct Target {
    Target(uint64_t rrcount, uint32_t pid) : rrcount(rrcount), pid(pid) {}
    uint64_t rrcount;
    uint32_t pid;
    uint32_t asid;
    std::string name;
};

class CompareTarget {
  public:
    bool operator()(const Target &t1, const Target &t2) {
        return t1.rrcount > t2.rrcount;
    }
};

std::priority_queue<Target, std::vector<Target>, CompareTarget> target_queue;

inline hwaddr roundUpToPageSize(hwaddr addr, hwaddr pagesize) {
    const hwaddr pagemask = ~(pagesize - 1);
    return (addr % pagesize > 0) ? ((addr + pagesize) & pagemask) : addr;
}

std::vector<target_ulong> pandapy_callstack(){
    std::vector<target_ulong> current_callstack(10);
    int callstacksize =
        get_functions(current_callstack.data(),
                    static_cast<int>(current_callstack.size()), current_cpu);
    current_callstack.resize(callstacksize);
    return current_callstack;
}

py::bytes pandapy_read_physical(hwaddr start, hwaddr length) {
    std::string buf;
    buf.resize(length);

    uint8_t *buffer_cursor = (uint8_t *)buf.data();
    memset(buffer_cursor, 0, length);

    const hwaddr PAGE_SIZE = TARGET_PAGE_SIZE;
    hwaddr end = start + length;
    end = std::min(end, ram_size);

    hwaddr current = start;

    // pagealign
    hwaddr bytesToNextPage = roundUpToPageSize(current, PAGE_SIZE) - current;
    hwaddr firstChunkEnd = std::min(current + bytesToNextPage, end);
    hwaddr firstChunkLen = firstChunkEnd - current;

    int res =
        panda_physical_memory_rw(current, buffer_cursor, firstChunkLen, 0);
    if (res == -1) {
        memset(buffer_cursor, 0, firstChunkLen);
    }

    buffer_cursor += firstChunkLen;
    current += firstChunkLen;

    // copy whole pages until the end
    while (current < end) {
        hwaddr remaining = end - current;
        hwaddr chunk_size = std::min(remaining, PAGE_SIZE);

        int res =
            panda_physical_memory_rw(current, buffer_cursor, chunk_size, 0);
        if (res == -1) {
            memset(buffer_cursor, 0, chunk_size);
        }

        current += chunk_size;
        buffer_cursor += chunk_size;
    }

    return py::bytes(buf);
}

PYBIND11_EMBEDDED_MODULE(panda, m) {
    m.doc() = "pandapy memory access";
    m.def("read", &pandapy_read_physical, "reads length from address");
    m.def("memory_size", []() { return ram_size; });
    m.def("get_rr_count", &rr_get_guest_instr_count);
    m.def("callstack", &pandapy_callstack, "reads the current callstack");
}

py::module pymodule;

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (target_queue.empty()) {
        rr_end_replay_requested = 1;
        return false;
    }

    const auto &top_target = target_queue.top();
    uint64_t rrcount = rr_get_guest_instr_count();
    if (rrcount >= top_target.rrcount) {
        pymodule.attr("run")(top_target.pid);
        target_queue.pop();
    }

    return true;
}

/* Plugin initialization */
void *plugin_self;

void parseTargetLine(const std::string& line){
    try {
        uint64_t rrcount;
        uint32_t pid;

        auto obj = nlohmann::json::parse(line);

        pid = obj["pid"];
        if(obj.count("rrcount")){
            rrcount = obj["rrcount"];
        } else if(obj.count("last_instruction")){
            rrcount = obj["last_instruction"];
        } else {
            throw std::invalid_argument("no rrcount found");
        }

        target_queue.push(Target(rrcount, pid));
        std::cout << "Parsed " << rrcount << " " << pid << std::endl;

    } catch (std::invalid_argument& e) {
        std::cerr << "invalid target: " << e.what() << std::endl;
    }
}

void parseTargets(const std::string& file){
    std::ifstream input(file);
    std::string line;
    while (std::getline(input, line)){
        if(line.empty()) continue;
        parseTargetLine(line);
    }
}

bool init_plugin(void *self) {
    plugin_self = self;

    panda_require("callstack_instr");
    assert(init_callstack_instr_api());

    panda_cb pcb;
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    panda_arg_list *args = panda_get_args("procinfodump");
    const char* filename = panda_parse_string_opt(args, "file", "pids.txt", "file where to take the targets from");
    uint64_t breakpoint = panda_parse_uint64_opt(args, "break", 0, "set a breakpoint, execute a shell and exit");

    if(breakpoint){
        Target exampletarget(breakpoint, 0);
        target_queue.push(exampletarget);
    } else {
        parseTargets(filename);
    }

    py::initialize_interpreter(true);
    pymodule = py::module::import("main");

    return true;
}

void uninit_plugin(void *self) {
    (void)self;
    py::finalize_interpreter();
}
