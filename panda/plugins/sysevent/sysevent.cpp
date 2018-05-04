/**
* This plugin listens for hypercalls and emits SYSENTER/SYSEXIT events
*/

#include "panda/plugin.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include <json.hpp>
#include <map>
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>

extern "C" {
#include "sysevent.h"
bool init_plugin(void *);   
void uninit_plugin(void *);
int guest_hypercall_callback(CPUState *cpu);

PPP_PROT_REG_CB(on_sysevent_enter);
PPP_PROT_REG_CB(on_sysevent_exit);
PPP_PROT_REG_CB(on_sysevent_notif);
}

// this creates BOTH the global for this callback fn (on_ssm_func)
// and the function used by other plugins to register a fn (add_on_ssm)
PPP_CB_BOILERPLATE(on_sysevent_enter);
PPP_CB_BOILERPLATE(on_sysevent_exit);
PPP_CB_BOILERPLATE(on_sysevent_notif);

#define HYPERCALL_SYSCALL_ENTER 1
#define HYPERCALL_SYSCALL_EXIT 2
#define HYPERCALL_NOTIF 4
#define SYSTAINT_MAGIC 0xffaaffcc

struct ProcessData {
    OsiProc* proc = nullptr;
    uint64_t first_instruction = 0;
    uint64_t last_instruction = 0;
    nlohmann::json mmap;
};

// Arguments
static bool start_recording;
static bool record_pids;
static bool log_events;

static std::ofstream pids_outfp;
static std::ofstream events_outfp;

// Data structures
static std::map<target_ulong, ProcessData> pids;

static nlohmann::json get_modules(CPUState *cpu, OsiProc* proc){
    OsiModules *ms = get_libraries(cpu, proc);
    std::vector<nlohmann::json> calls;


    if (ms == NULL) {
        printf("No mapped dynamic libraries.\n");
    } else {
        for (target_ulong i = 0; i < ms->num; i++){
            nlohmann::json call;
            call["base"] = ms->module[i].base;
            call["size"] = ms->module[i].size;
            call["name"] = ms->module[i].name;
            call["file"] = ms->module[i].file;
            calls.push_back(call);
        }
    }

    //free_osimodules(ms);
    nlohmann::json ret = calls;
    return ret;
}

static void on_enter_extra(CPUState *cpu, uint32_t eventid){
    if(start_recording){
        if(rr_mode == RR_OFF){
            std::cout << "Start recording" << std::endl;
            rr_record_requested = 1;
            rr_requested_name = g_strdup("sysrec");
        }
    }
}

#ifdef TARGET_I386
void hypercall_event_listener(CPUState *cpu){
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;

    if(!(env->regs[R_EAX] == SYSTAINT_MAGIC || env->regs[R_EAX] == 0x42424242))
        return;

    printf("HYPERCALL " TARGET_FMT_ld " " TARGET_FMT_ld " " TARGET_FMT_ld "\n",
         env->regs[R_EBX], env->regs[R_ECX], env->regs[R_EDX]);

    uint32_t event_id = env->regs[R_ECX];

    uint32_t buffer_address = env->regs[R_EDX];
    uint32_t buffer_len = env->regs[R_ESI];

    const char* etype = nullptr;

    switch (env->regs[R_EBX]) {
        case HYPERCALL_SYSCALL_ENTER:
            //printf("SYSEVENT enter: %" PRIu32 " \n", cuckoo_event);
            etype = "enter";
            on_enter_extra(cpu, event_id);
            PPP_RUN_CB(on_sysevent_enter, cpu, event_id);
        break;
        case HYPERCALL_SYSCALL_EXIT:
             //printf("SYSEVENT exit: %" PRIu32 " \n", cuckoo_event);
            etype = "exit";
            PPP_RUN_CB(on_sysevent_exit, cpu, event_id);
        break;
        case HYPERCALL_NOTIF:
            etype = "notif";
            PPP_RUN_CB(on_sysevent_notif, cpu, event_id, buffer_address, buffer_len);
        break;
        default:
            etype = "error";
        break;
    }

    if(log_events){
        nlohmann::json event;
        if(etype){
            event["type"] = etype;
        } else {
            event["type"] = env->regs[R_EBX];
            event["eax"] = env->regs[R_EAX];
        }
        event["rrcount"] = rr_get_guest_instr_count();
        event["id"] = env->regs[R_ECX];
        event["asid"] = panda_current_asid(cpu);
        event["pc"] = cpu->panda_guest_pc;
        events_outfp << event.dump() << std::endl;
    }

    if(record_pids &&
        (env->regs[R_EBX] == HYPERCALL_SYSCALL_ENTER ||
         env->regs[R_EBX] == HYPERCALL_NOTIF)){

        OsiProc * proc = get_current_process(cpu);
        if(proc && (proc->pid > 4)){
            auto& p = pids[proc->pid];
            p.proc = proc;
            const uint64_t guest_icount = rr_get_guest_instr_count();
            p.last_instruction = guest_icount;

            if (p.first_instruction == 0){
                p.first_instruction = guest_icount;
                p.mmap = get_modules(cpu, p.proc);
            }
        }
    }
}
#endif

int guest_hypercall_callback(CPUState *cpu){
#ifdef TARGET_I386
    hypercall_event_listener(cpu);
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

    panda_arg_list *args = panda_get_args("sysevent");
    start_recording = panda_parse_bool_opt(args, "start_recording", "start recording on first sysevent");
    record_pids = panda_parse_bool_opt(args, "record_pids", "monitor pid-asid correspondence");
    log_events = panda_parse_bool_opt(args, "log_events", "log events to file");

    const char* output_file = panda_parse_string_opt(args, "outf", nullptr, "monitor pid-asid correspondence");

    if(output_file){
        pids_outfp.open(output_file);
    }

    if(log_events){
        events_outfp.open("events.txt");
    }

    if(record_pids){
        panda_require("osi");
        assert(init_osi_api());
    }

    return true;
}


void uninit_plugin(void *self) {
    (void) self;
    if(record_pids){
        std::ostream& out = pids_outfp.is_open()? pids_outfp : std::cout;

        for (auto const& x : pids)
        {
            nlohmann::json result;
            const auto& proc = x.second;

            result["pid"] = x.first;
            result["asid"] = proc.proc->asid;
            if(proc.proc->name)
                result["name"] = proc.proc->name;
            else
                result["name"] = "unknown";

            result["first_instruction"] = proc.first_instruction;
            result["last_instruction"] = proc.last_instruction;
            //result["mmap"] = proc.mmap;

            out << result << std::endl;
            //free_osiproc(proc.proc);
        }
    }
    if(log_events){
        events_outfp.close();
    }
}

