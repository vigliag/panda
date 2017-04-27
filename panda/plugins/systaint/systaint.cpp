
#include "panda/plugin.h" //include plugin api we are implementing
#include "taint2/taint2.h" //include taint2 module we'll use

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
#include "taint2/taint2_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
int guest_hypercall_callback(CPUState *cpu);
}

#define HYPERCALL_SYSCALL_ENTER 1
#define HYPERCALL_SYSCALL_EXIT 2
#define SYSTAINT_MAGIC 0xffaaffcc

// we track a single syscall and process at a time
uint32_t current_syscall = 0;
uint32_t current_asid = 0;

// counters have an idea of how many read and writes we are talking about
int n_mem_writes_to_taint = 0;
int n_mem_reads_to_query = 0;

#ifdef TARGET_I386

void i386_hypercall_callback(CPUState *cpu){
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;

    if(env->regs[R_EAX] != SYSTAINT_MAGIC)
        return;

    bool entering = env->regs[R_EBX] == HYPERCALL_SYSCALL_ENTER ? true : false;
    uint32_t syscall_id = env->regs[R_ECX];

    //printf("HYPERCALL " TARGET_FMT_ld " " TARGET_FMT_ld " " TARGET_FMT_ld "\n",
    //     env->regs[R_EBX], env->regs[R_ECX], env->regs[R_EDX]);

    target_ulong asid = panda_current_asid(ENV_GET_CPU(env));
    printf(TARGET_FMT_ld " ", asid);
    current_asid = asid; //TODO this should be made into a set

    if(entering){

        if (!taint2_enabled()) {
            printf ("enabling taint\n");
            taint2_enable_taint();           
        }

        if(!current_syscall){
            // we are entering a new, top-level syscall
            printf("SYSCALL enter: %" PRIu32 " \n", syscall_id);
            current_syscall = syscall_id;

        } else {
            // we are already in a syscall and we are detecting another
            printf("SYSCALL ignored  %" PRIu32 " \n", syscall_id);
        } 

    } else {
        
        if(current_syscall == syscall_id){
            printf("SYSCALL exit: %" PRIu32 " \n", syscall_id);
            current_syscall = 0;
        }
    }

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

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    CPUArchState *archEnv = (CPUArchState*)env->env_ptr;
    
    if(!current_syscall){
        return 0;
    }

    if (current_asid != panda_current_asid(ENV_GET_CPU(archEnv)) ){
        return 0;
    }

    n_mem_writes_to_taint++;
    
    //for(target_ulong i=0; i<size; i++){
    //    taint2_label_ram(addr + i, current_syscall);
    //}

    return 0;
}


int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size) {
    CPUArchState *archEnv = (CPUArchState*)env->env_ptr;

    if(!current_syscall){
        return 0;
    }

    if (current_asid != panda_current_asid(ENV_GET_CPU(archEnv)) ){
        return 0;
    }
    
    n_mem_reads_to_query++;

    return 0;
}


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

    panda_enable_memcb();
    pcb.virt_mem_after_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);
    pcb.virt_mem_before_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);
    
    // this sets up the taint api fn ptrs so we have access
    panda_require("taint2");
    assert(init_taint2_api());

    //panda_arg_list *args = panda_get_args("systaint");
    //panda_require("callstack_instr");
    //assert(init_callstack_instr_api());

    return true;
}


void uninit_plugin(void *self) {
    printf("un_initing systaint, reads %d, writes %d",
        n_mem_reads_to_query, n_mem_writes_to_taint);
}
