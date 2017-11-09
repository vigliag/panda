#include "panda/plugin.h"
#include "tcgtaint.hpp"
#include "cpu.h"
#include "logging.hpp"
#include "tcg-taint/tcg-taint.h"
#include "tcgtaint_int_fns.h"

void tcgtaint_taint_register(bool istmp, unsigned char regno, int label) {
  tcgtaint_ctx.taint_engine->setTaintedRegister(label, istmp, regno);
}

void tcgtaint_taint_virtual_memory(target_ulong addr, unsigned int size, int label) {
  hwaddr phyaddr = panda_virt_to_phys(current_cpu, addr);
  if (phyaddr == static_cast<hwaddr>(-1)) {
    WARNING("VA %.8x is invalid, can't taint it", addr);
    return;
  }
  tcgtaint_ctx.taint_engine->setTaintedMemory(label, phyaddr, size);
}

void tcgtaint_taint_physical_memory(hwaddr phyaddr, unsigned int size, int label) {
    tcgtaint_ctx.taint_engine->setTaintedMemory(label, phyaddr, size);
}

void tcgtaint_clear_physical_memory(hwaddr phyaddr, unsigned int size) {
    tcgtaint_ctx.taint_engine->clearMemory(phyaddr, size);
}

void tcgtaint_set_taint_status(bool status){
    taint_is_user_enabled = status;
    if(status){
        tcg_taint_instrumentation_enable();
    } else {
        tcg_taint_instrumentation_disable();
    }
}

bool tcgtaint_is_taint_instrumentation_on(void){
    return qtrace_taint_instrumentation_enabled;
}

bool tcgtaint_is_taint_enabled(bool status){
    return taint_is_user_enabled;
}

bool tcgtaint_is_virtual_memory_tainted(target_ulong addr) {
  hwaddr phyaddr = panda_virt_to_phys(current_cpu, addr);
  if (phyaddr == static_cast<hwaddr>(-1)) {
    return false;
  }
  return tcgtaint_ctx.taint_engine->isTaintedMemory(phyaddr);
}

size_t tcgtaint_get_physical_memory_labels_count(target_ulong addr){
    const std::set<int> *memoryLabels = tcgtaint_ctx.taint_engine->getMemoryLabels(addr);
    if(memoryLabels){
        return memoryLabels->size();
    } else {
        return 0;
    }
}

void tcgtaint_physical_memory_labels_copy(target_ulong addr, uint32_t* out){
    const std::set<int> *memoryLabels = tcgtaint_ctx.taint_engine->getMemoryLabels(addr);
    if(memoryLabels){
        int i = 0;
        for(const int& label: *memoryLabels){
            out[i] = (uint32_t) label;
            i++;
        }
    }
}
