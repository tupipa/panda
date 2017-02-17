/*
 * plugin: trace_instrblock
 * 
 * This plugin is used to print all instructions during the replay.
 * It disassembles the instructions using tool capstone
 * 
 */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include <capstone/capstone.h>

#include <map>
#include <string>

//typedef std::map<std::string,int> instr_hist;


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#define WINDOW_SIZE 100

csh handle;
cs_insn *insn;
bool init_capstone_done = false;
target_ulong asid;
int sample_rate = 100;
FILE *histlog;

#define MAX_POOL 1<<10
typedef struct ipool{
	cs_insn * insn;
	size_t count;
}ipool;

ipool ins_pool[MAX_POOL];
uint64_t pool_size=0;

// PC => Mnemonic histogram
//std::map<target_ulong,cs_insn> code_hists;

// PC => number of instructions in the TB
//std::map<target_ulong,int> tb_insns;

// Circular buffer PCs in the window
//target_ulong window[WINDOW_SIZE] = {};

// Rolling histogram of PCs
//instr_hist window_hist;
//uint64_t window_insns = 0;
//uint64_t bbcount = 0;

void init_capstone(CPUState *cpu) {
    cs_arch arch;
    cs_mode mode;
    CPUArchState* env = (CPUArchState *) cpu->env_ptr;
#ifdef TARGET_I386
    arch = CS_ARCH_X86;
    mode = env->hflags & HF_LMA_MASK ? CS_MODE_64 : CS_MODE_32;
#elif defined(TARGET_ARM)
    arch = CS_ARCH_ARM;
    mode = env->thumb ? CS_MODE_THUMB : CS_MODE_ARM;
#endif

    if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
        printf("Error initializing capstone\n");
    }
    init_capstone_done = true;
}

/*
void add_hist(instr_hist &a, instr_hist &b) {
    for (auto &kvp : b) a[kvp.first] += kvp.second;
}

void sub_hist(instr_hist &a, instr_hist &b) {
    for (auto &kvp : b) a[kvp.first] -= kvp.second;
}
*/

void print_ins_pool() { 
    if (pool_size < 1) return;

    fprintf(histlog, "\nInsCount:%" PRIu64 "\n", rr_get_guest_instr_count());
    //fprintf(histlog, "{");
    //for (auto &kvp : ih) {
    //    fprintf (histlog, "\"%s\": %f, ", kvp.first.c_str(), kvp.second/(float)window_insns);
    //}
    //fprintf(histlog, "}\n");
    uint64_t instr_cnt=0;
    for (int i=0; i<pool_size; i++){
	for (int j=0; j< ins_pool[i].count; j++){
	    fprintf (histlog, "0x%" PRIx64":\t%s\t%s\n",
		ins_pool[i].insn[j].address,
	      	ins_pool[i].insn[j].mnemonic, 
		ins_pool[i].insn[j].op_str);
		instr_cnt++;
	}
	cs_free (ins_pool[i].insn, ins_pool[i].count);
    }
    
    fprintf(histlog, "pool printed, %" PRId64 " disams(%" PRId64 " instrs) \n", pool_size, instr_cnt);

}

// During retranslation we may end up with different
// instructions. Since we don't have TB generations we just
// remove it from the rolling histogram first.
/*
void clear_hist(target_ulong pc) {
    for (int i = 0; i < WINDOW_SIZE; i++) {
        if (window[i] == pc) {
            window[i] = 0;
            window_insns -= tb_insns[pc];
            sub_hist(window_hist, code_hists[pc]);
        }
    }
}
*/
void clear_ins_pool() {
	pool_size=0;
}

static int after_block_translate(CPUState *cpu, TranslationBlock *tb) {
    //size_t count;
    uint8_t mem[1024] = {};

    if (asid && panda_current_asid(cpu) != asid) return 0;

    if (!init_capstone_done) init_capstone(cpu);

//    if (ins_pool[pool_size](tb->pc) != code_hists.end()) {
//	//what's this? check different block?
//        clear_pool(tb->pc);
//        return 0;
//    }

    panda_virtual_memory_rw(cpu, tb->pc, mem, tb->size, false);
    size_t count = cs_disasm(handle, mem, tb->size, tb->pc, 0, &insn);

    if( pool_size >= MAX_POOL){
	print_ins_pool();
	clear_ins_pool();
    }

    ins_pool[pool_size].insn=insn;
    ins_pool[pool_size].count=count;
    pool_size++;

    return 1;
}

/*
static int before_block_exec(CPUState *cpu, TranslationBlock *tb) {
    if (asid && panda_current_asid(cpu) != asid) return 0;

    if (window[bbcount % WINDOW_SIZE] != 0) {
        target_ulong old_pc = window[bbcount % WINDOW_SIZE];
        window_insns -= tb_insns[old_pc];
        sub_hist(window_hist, code_hists[old_pc]);
    }

    window[bbcount % WINDOW_SIZE] = tb->pc;
    window_insns += tb_insns[tb->pc];
    add_hist(window_hist, code_hists[tb->pc]);

    bbcount++;

    if (bbcount % sample_rate == 0) {
        // write out to the histlog
        print_hist(window_hist, window_insns);
    }
    return 1;
}*/

bool init_plugin(void *self) {
    panda_cb pcb;
    
    printf("in init_plugin..\n");
    panda_arg_list *args = panda_get_args("trace_instrblock");
    const char *name = panda_parse_string(args, "name", "trace_instblock");
    asid = panda_parse_ulong(args, "asid", 0);
    sample_rate = panda_parse_uint32(args, "sample_rate", 1000);

    char fname[260];
    sprintf(fname, "%s_out.txt", name);
    histlog = fopen(fname, "w");

    fprintf (histlog, "asid: 0x" TARGET_FMT_lx "\n", asid);
    fprintf (histlog, "address:\tmnemonic\top_str\n");


    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
   // pcb.before_block_exec = before_block_exec;
   // panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) {
    //print_hist(window_hist, window_insns);
    print_ins_pool();
    fclose(histlog);
}
