/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

//This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS


#include "panda/plugin.h"
#include "monitor/monitor.h"
#include "disas/disas.h"
#include "cpu.h"
#include "panda/rr/rr_log.h"

#include "trace_sample_int_fns.h"

bool translate_callback(CPUState *env, target_ulong pc);
int exec_callback(CPUState *env, target_ulong pc);

bool init_plugin(void *);
void uninit_plugin(void *);

bool active = true;
long long begin_at = 0;
long long exit_at = -1;
FILE *plugin_log;

// We're going to log all user instructions
bool translate_callback(CPUState *env, target_ulong pc) {
    // We have access to env here, so we could choose to
    // read the bytes and do something fancy with the insn
    //return pc > 0x80000000;
    //printf("in translate_callback\n");  
    return true;
}

int exec_callback(CPUState *env, target_ulong pc) {
    if (!active) return 1;
    fprintf(plugin_log, "pc: 0x" TARGET_FMT_lx " executed:", pc);
    printf("pc: 0x" TARGET_FMT_lx " executed:", pc);
    // An x86 instruction must always fit in 15 bytes; this does not
    // make much sense for other architectures, but is just for
    // testing and debugging
    unsigned char buf[15];
    panda_virtual_memory_rw(env, pc, buf, 15, 0);
    int i;
    for (i = 0; i < 15; i++) {
        fprintf(plugin_log, " %02x", buf[i]);
    }
    fprintf(plugin_log, "\n");
    //return 1;
    return 0;
}


int sample_function(CPUState *env){
    printf("sample was passed a cpustate\n");
    return 0;
}

int other_sample_function(CPUState *env, int foo){
    printf("other was passed a cpustate and paramater %#X\n", foo);
    return 1;
}

panda_arg_list *args;

bool init_plugin(void *self) {
    panda_cb pcb;

    args = panda_get_args("trace_sample");
    printf("get args of trace_sample\n");
    const char *tblog_filename = panda_parse_string_opt (args, "file", "", "file name for log");
    printf("\nget file name \t%s\n\n", tblog_filename);
    
    if (!tblog_filename) {
        fprintf(stderr, "Plugin 'sample' needs argument: -panda trace_sample:file=<file>\n");
        return false;
    }else{
	fprintf(stderr, "\nGOOD\n");
    }

    plugin_log = fopen(tblog_filename, "w");    
    if(!plugin_log) return false;

    printf("file opened.....\n");

    //panda_do_flush_tb();
    //printf("do_flush_tb enabled\n");

    panda_enable_precise_pc();
    printf("precise_pc enabled\n");

    panda_enable_memcb();
    printf("memcb enabled\n");

    //pcb.monitor = monitor_callback;
    //panda_register_callback(self, PANDA_CB_MONITOR, pcb);

    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    printf("callback PANDA_CB_INSN_TRANSLATE registered.....\n");

    pcb.insn_exec = exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
    printf("callback PANDA_CB_INSN_EXEC registered.....\n");

//#ifdef CONFIG_ANDROID
//    pcb.before_loadvm = before_loadvm_callback;
//    panda_register_callback(self, PANDA_CB_BEFORE_REPLAY_LOADVM, pcb);
//#endif

    return true;
}

void uninit_plugin(void *self) {    

    printf("Unloading sample plugin.\n");
    printf("closing file.\n");
    fflush(plugin_log);
    fclose(plugin_log);
    printf("free args.\n");
    panda_free_args(args);
    printf("trace_sample unplugged.\n");

}


