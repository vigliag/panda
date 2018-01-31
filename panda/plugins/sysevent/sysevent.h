#pragma once

#include <stdint.h>

typedef void (*on_sysevent_enter_t)(CPUState *cpu, uint32_t eventid);
typedef void (*on_sysevent_exit_t)(CPUState *cpu, uint32_t eventid);
typedef void (*on_sysevent_notif_t)(CPUState *cpu, uint32_t eventid, uint32_t pointer, uint32_t len);
