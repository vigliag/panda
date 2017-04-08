#include "panda/plugin.h"
#include "taint2/taint2.h"


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

#include "taint2/taint2_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);

int guest_hypercall_callback(CPUState *cpu);

}


#ifdef TARGET_I386
// Support all features of label and query program
void i386_hypercall_callback(CPUState *cpu){
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;

    if(env->regs[R_EAX] != 0xffaaffcc)
        return;

    printf("HYPERCALL " TARGET_FMT_ld " " TARGET_FMT_ld " " TARGET_FMT_ld "\n",
         env->regs[R_EBX], env->regs[R_ECX], env->regs[R_EDX]);

    //target_ulong addr = panda_virt_to_phys(cpu, env->regs[R_EAX]);
    
    /*
    if ((int)addr == -1) {
        // if EAX is not a valid ptr, then it is unlikely that this is a
        // PandaHypercall which requires EAX to point to a block of memory
        // defined by PandaHypercallStruct
        printf ("cpuid with invalid ptr in EAX: vaddr=0x%x paddr=0x%x. Probably not a Panda Hypercall\n",
                (uint32_t) env->regs[R_EAX], (uint32_t) addr);
    }
    //panda_virtual_memory_rw(cpu, env->regs[R_EAX], (uint8_t *) &phs, sizeof(phs), false);
    */
    
}
#endif // TARGET_I386


int guest_hypercall_callback(CPUState *cpu){
#ifdef TARGET_I386
    i386_hypercall_callback(cpu);
#endif

#ifdef TARGET_ARM
    // TODO
#endif
    return 1;
}

void *plugin_self;

bool init_plugin(void *self) {
    plugin_self = self;
    panda_cb pcb;
   
    pcb.guest_hypercall = guest_hypercall_callback;
    panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb);
    
    //panda_arg_list *args = panda_get_args("systaint");

    //panda_require("callstack_instr");
    //assert(init_callstack_instr_api());

    return true;
}



void uninit_plugin(void *self) {

}
