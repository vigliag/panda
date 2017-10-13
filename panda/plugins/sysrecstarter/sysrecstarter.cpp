/**
* This plugin listens for hypercalls and emits SYSENTER/SYSEXIT events
*/

// DEPRECATED IN FAVOR OF SYSEVENT

#include "panda/plugin.h"
#include <iostream>
#include <fstream>
#include "panda/rr/rr_log_all.h"
#include "sysevent/sysevent.h"

extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

void systaint_event_enter(CPUState *cpu, uint32_t event_label){
    std::cout << "eenter" << std::endl;
    if(rr_mode == RR_OFF){
        std::cout << "Start recording" << std::endl;
        rr_record_requested = 1;
        rr_requested_name = g_strdup("sysrec");
    }
}

/* Plugin initialization */

void *plugin_self;
bool init_plugin(void *self) {
    plugin_self = self;
    panda_require("sysevent");
    PPP_REG_CB("sysevent", on_sysevent_enter, systaint_event_enter);
    return true;
}


void uninit_plugin(void *self) {

}

