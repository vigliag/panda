#ifndef SYSTAINT_HPP
#define SYSTAINT_HPP
#include <cstdint>

void systaint_event_enter(CPUState *cpu, uint32_t event_label);
void systaint_event_exit(CPUState *cpu, uint32_t event_label);

#endif // SYSTAINT_HPP
