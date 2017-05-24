#include "panda/plugin.h"

extern "C" {
#include "sysevent.h"
bool init_plugin(void *);
void uninit_plugin(void *);
int guest_hypercall_callback(CPUState *cpu);

PPP_PROT_REG_CB(on_sysevent_enter);
PPP_PROT_REG_CB(on_sysevent_exit);
}

// this creates BOTH the global for this callback fn (on_ssm_func)
// and the function used by other plugins to register a fn (add_on_ssm)
PPP_CB_BOILERPLATE(on_sysevent_enter);
PPP_CB_BOILERPLATE(on_sysevent_exit);

#define HYPERCALL_SYSCALL_ENTER 1
#define HYPERCALL_SYSCALL_EXIT 2
#define SYSTAINT_MAGIC 0xffaaffcc

#ifdef TARGET_I386
void hypercall_event_listener(CPUState *cpu){
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;

    if(env->regs[R_EAX] != SYSTAINT_MAGIC)
        return;

    //printf("HYPERCALL " TARGET_FMT_ld " " TARGET_FMT_ld " " TARGET_FMT_ld "\n",
    //     env->regs[R_EBX], env->regs[R_ECX], env->regs[R_EDX]);


    bool entering = env->regs[R_EBX] == HYPERCALL_SYSCALL_ENTER ? true : false;
    uint32_t cuckoo_event = env->regs[R_ECX];

    if(entering){
        printf("SYSEVENT enter: %" PRIu32 " \n", cuckoo_event);
        PPP_RUN_CB(on_sysevent_enter, cpu, cuckoo_event);
    }

    if(!entering){
        printf("SYSEVENT exit: %" PRIu32 " \n", cuckoo_event);
        PPP_RUN_CB(on_sysevent_exit, cpu, cuckoo_event);
    }
}
#endif

int guest_hypercall_callback(CPUState *cpu){
#ifdef TARGET_I386
    hypercall_event_listener(cpu);
#endif

#ifdef TARGET_ARM
    // TODO
#endif
    return 1;
}

/* Plugin initialization */

void *plugin_self;
bool init_plugin(void *self) {
    plugin_self = self;

    panda_cb pcb;
    pcb.guest_hypercall = guest_hypercall_callback;
    panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb);

    return true;
}


void uninit_plugin(void *self) {

}

