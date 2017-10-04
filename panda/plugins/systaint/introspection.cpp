#include "introspection.hpp"

#define KMODE_FS           0x030 // Segment number of FS in kernel mode
#define KPCR_CURTHREAD_OFF 0x124 // _KPCR.PrcbData.CurrentThread
#define KTHREAD_PTEB_OFF   0x88 //from volatility win7sp1
#define TEB_THREADID_OFF   0x24

#ifdef TARGET_I386
uint32_t get_kpcr(CPUState *cpu) {
    // Read the kernel-mode FS segment base
    uint32_t e1, e2;
    uint32_t fs_base;

    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    // Read out the two 32-bit ints that make up a segment descriptor
    panda_virtual_memory_rw(cpu, env->gdt.base + KMODE_FS, (uint8_t *)&e1, sizeof(e1), false);
    panda_virtual_memory_rw(cpu, env->gdt.base + KMODE_FS + 4, (uint8_t *)&e2, sizeof(e2), false);

    // Turn wacky segment into base
    fs_base = (e1 >> 16) | ((e2 & 0xff) << 16) | (e2 & 0xff000000);

    return fs_base;
}

uint32_t get_current_thread_id(CPUState *cpu) {
    uint32_t kthread_kpcr_curthread, pteb, thread_id;
    uint32_t kpcr = get_kpcr(cpu);

    panda_virtual_memory_rw(cpu, kpcr+KPCR_CURTHREAD_OFF, (uint8_t *)&kthread_kpcr_curthread, sizeof(kthread_kpcr_curthread), false);
    panda_virtual_memory_rw(cpu, kthread_kpcr_curthread+KTHREAD_PTEB_OFF, (uint8_t *)&pteb, sizeof(pteb), false);
    panda_virtual_memory_rw(cpu, pteb+TEB_THREADID_OFF, (uint8_t*)&thread_id, sizeof(thread_id), false);

    return thread_id;
}

bool isUserSpaceAddress(uint64_t virt_addr){
    const uint64_t MMUserProbeAddress = 0x7fff0000; // Start of kernel memory
    return virt_addr < MMUserProbeAddress;
}
#endif
