#ifndef INTROSPECTION_HPP
#define INTROSPECTION_HPP

#include "panda/plugin.h"

#ifdef TARGET_I386
// XXX: this will have to change for 64-bit
uint32_t get_kpcr(CPUState *cpu);

uint32_t get_current_thread_id(CPUState *cpu);

/* On windows, checks if a virtual address is in user-space */
bool isUserSpaceAddress(uint64_t virt_addr);

#endif

#endif // INTROSPECTION_HPP
