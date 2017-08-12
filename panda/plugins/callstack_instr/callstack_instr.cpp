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
#define __STDC_FORMAT_MACROS

#include <cstdio>
#include <cstdlib>

#include <map>
#include <set>
#include <vector>
#include <algorithm>

#include <capstone/capstone.h>
#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#elif defined(TARGET_PPC)
#include <capstone/ppc.h>
#endif

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "callstack_instr.h"

extern "C" {
#include "panda/plog.h"

#include "callstack_instr_int_fns.h"

bool translate_callback(CPUState* cpu, target_ulong pc);
int exec_callback(CPUState* cpu, target_ulong pc);
int before_block_exec(CPUState* cpu, TranslationBlock *tb);
int after_block_exec(CPUState* cpu, TranslationBlock *tb);
int after_block_translate(CPUState* cpu, TranslationBlock *tb);

bool init_plugin(void *);
void uninit_plugin(void *);

PPP_PROT_REG_CB(on_call);
PPP_PROT_REG_CB(on_ret);
PPP_PROT_REG_CB(on_call2);
PPP_PROT_REG_CB(on_ret2);

}

PPP_CB_BOILERPLATE(on_call);
PPP_CB_BOILERPLATE(on_ret);

PPP_CB_BOILERPLATE(on_call2);
PPP_CB_BOILERPLATE(on_ret2);

enum instr_type {
  INSTR_UNKNOWN = 0,
  INSTR_CALL,
  INSTR_RET,
  INSTR_SYSCALL,
  INSTR_SYSRET,
  INSTR_SYSENTER,
  INSTR_SYSEXIT,
  INSTR_INT,
  INSTR_IRET,
};

struct stack_entry {
    target_ulong pc;
    instr_type kind;
};

#define MAX_STACK_DIFF 5000

csh cs_handle_32;
csh cs_handle_64;

bool has_ret_after_block = false;

bool init_capstone_done = false;

// Track the different stacks we have seen to handle multiple threads
// within a single process.
std::map<target_ulong,std::set<target_ulong>> stacks_seen;

// Use a typedef here so we can switch between the stack heuristic and
// the original code easily
#ifdef USE_STACK_HEURISTIC
typedef std::pair<target_ulong,target_ulong> stackid;
target_ulong cached_sp = 0;
target_ulong cached_asid = 0;
#else
typedef target_ulong stackid;
#endif

// stackid -> shadow stack
std::map<stackid, std::vector<stack_entry>> callstacks;
// stackid -> function entry points
std::map<stackid, std::vector<target_ulong>> function_stacks;
// EIP -> instr_type
std::map<target_ulong, instr_type> call_cache;
int last_ret_size = 0;

static inline bool in_kernelspace(CPUArchState* env) {
#if defined(TARGET_I386)
    return ((env->hflags & HF_CPL_MASK) == 0);
#elif defined(TARGET_ARM)
    return ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC);
#else
    return false;
#endif
}

static inline target_ulong get_stack_pointer(CPUArchState* env) {
#if defined(TARGET_I386)
    return env->regs[R_ESP];
#elif defined(TARGET_ARM)
    return env->regs[13];
#else
    return 0;
#endif
}

static stackid get_stackid(CPUArchState* env) {
#ifdef USE_STACK_HEURISTIC
    target_ulong asid;

    // Track all kernel-mode stacks together
    if (in_kernelspace(env))
        asid = 0;
    else
        asid = panda_current_asid(ENV_GET_CPU(env));

    // Invalidate cached stack pointer on ASID change
    if (cached_asid == 0 || cached_asid != asid) {
        cached_sp = 0;
        cached_asid = asid;
    }

    target_ulong sp = get_stack_pointer(env);

    // We can short-circuit the search in most cases
    if (std::abs(sp - cached_sp) < MAX_STACK_DIFF) {
        return std::make_pair(asid, cached_sp);
    }

    auto &stackset = stacks_seen[asid];
    if (stackset.empty()) {
        stackset.insert(sp);
        cached_sp = sp;
        return std::make_pair(asid,sp);
    }
    else {
        // Find the closest stack pointer we've seen
        auto lb = std::lower_bound(stackset.begin(), stackset.end(), sp);
        target_ulong stack1 = *lb;
        lb--;
        target_ulong stack2 = *lb;
        target_ulong stack = (std::abs(stack1 - sp) < std::abs(stack2 - sp)) ? stack1 : stack2;
        int diff = std::abs(stack-sp);
        if (diff < MAX_STACK_DIFF) {
            return std::make_pair(asid,stack);
        }
        else {
            stackset.insert(sp);
            cached_sp = sp;
            return std::make_pair(asid,sp);
        }
    }
#else
    return panda_current_asid(ENV_GET_CPU(env));
#endif
}



void init_capstone(CPUState *cpu) {
//     cs_arch arch;
//     cs_mode mode;
//     CPUArchState* env = (CPUArchState *) cpu->env_ptr;
// #ifdef TARGET_I386
//     arch = CS_ARCH_X86;
//     mode = env->hflags & HF_LMA_MASK ? CS_MODE_64 : CS_MODE_32;
// #elif defined(TARGET_ARM)
//     arch = CS_ARCH_ARM;
//     mode = env->thumb ? CS_MODE_THUMB : CS_MODE_ARM;
// #endif

//     if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
//         printf("ERROR initializing capstone\n");
//     }

#if defined(TARGET_I386)
    printf("callstack_instr: %s: i386 arch.\n", __FUNCTION__);
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
#if defined(TARGET_X86_64)
    printf("callstack_instr: %s: x86_64 arch.\n", __FUNCTION__);
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle_64) != CS_ERR_OK)
#endif
#elif defined(TARGET_ARM)
    printf("callstack_instr: %s: ARM arch.\n", __FUNCTION__);
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cs_handle_32) != CS_ERR_OK)
#elif defined(TARGET_PPC)
    printf("callstack_instr: %s: PPC arch.\n", __FUNCTION__);
    if (cs_open(CS_ARCH_PPC, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
#endif
    {
    printf("ERROR initializing capstone\n");
    return ;
    }   

    // Need details in capstone to have instruction groupings
    // cs_option(cs_handle_32, CS_OPT_DETAIL, CS_OPT_ON);

    if (cs_option(cs_handle_32, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK){
        printf("ERROR cs_option 32 bit\n");
        return false;
    }
#if defined(TARGET_X86_64)
    // cs_option(cs_handle_64, CS_OPT_DETAIL, CS_OPT_ON);
    if (cs_option(cs_handle_64, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK){
            printf("ERROR cs_optin for x86_64\n");
            return false;
    }
#endif


    // #if defined(TARGET_I386)
    //     printf("%s: i386 arch.\n", __FUNCTION__);
    //     if (cs_open(CS_ARCH_X86, CS_MODE_32, &csh_hd_32) != CS_ERR_OK)
    //     #if defined(TARGET_X86_64)
    //         printf("%s: x86_64 arch.\n", __FUNCTION__);
    //         if (cs_open(CS_ARCH_X86, CS_MODE_64, &csh_hd_64) != CS_ERR_OK)
    //     #endif
    // #elif defined(TARGET_ARM)
    //     printf("%s: ARM arch.\n", __FUNCTION__);
    //     if (cs_open(CS_ARCH_ARM, CS_MODE_32, &csh_hd_32) != CS_ERR_OK)
    // #elif defined(TARGET_PPC)
    //     printf("%s: PPC arch.\n", __FUNCTION__);
    //     if (cs_open(CS_ARCH_PPC, CS_MODE_32, &csh_hd_32) != CS_ERR_OK)
    // #endif
    //      {
    //         printf("ERROR initializing capstone\n");
    //         return ;
    //      }   

    //     // Need details in capstone to have instruction groupings
    //     if (cs_option(csh_hd_32, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK){
    //         printf("ERROR cs_option 32 bit\n");
    //         return ;
    //     }
    // #if defined(TARGET_X86_64)
    //     if (cs_option(csh_hd_64, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK){
    //         printf("ERROR cs_optin for x86_64\n");
    //         return ;
    //     }
    // #endif

    printf("callstack_instr: %s: done initializing capstone.\n", __FUNCTION__);
    init_capstone_done = true;
}



instr_type disas_block(CPUArchState* env, target_ulong pc, int size) {
    unsigned char *buf = (unsigned char *) malloc(size);
    int err = panda_virtual_memory_rw(ENV_GET_CPU(env), pc, buf, size, 0);
    if (err == -1) printf("Couldn't read TB memory!\n");
    instr_type res = INSTR_UNKNOWN;

#if defined(TARGET_I386)
    csh handle = (env->hflags & HF_LMA_MASK) ? cs_handle_64 : cs_handle_32;
#elif defined(TARGET_ARM)
    csh handle = cs_handle_32;

    if (env->thumb){
        cs_option(handle, CS_OPT_MODE, CS_MODE_THUMB);
    }
    else {
        cs_option(handle, CS_OPT_MODE, CS_MODE_ARM);
    }

#elif defined(TARGET_PPC)
    csh handle = cs_handle_32;
#endif

    cs_insn *insn;
    cs_insn *end;
    size_t count = cs_disasm(handle, buf, size, pc, 0, &insn);


    cs_err err_= cs_errno(handle);
    if (err_ != CS_ERR_OK){
        printf("ERROR in cs_disasm: ");
        switch(err_){
            case CS_ERR_MEM:
                printf("Out-Of-Memory error: cs_disasm\n");
                break;
            case CS_ERR_CSH:
                printf("Invalid csh argument: cs_close(), cs_errno(), cs_option()\n");
                break;
            case CS_ERR_DETAIL:
                printf("Information is unavailable because detail option is OFF\n") ;  // Information is unavailable because detail option is OFF
                break;
            case CS_ERR_MEMSETUP:
                printf("Dynamic memory management uninitialized \n"); // Dynamic memory management uninitialized (see CS_OPT_MEM)
                break;
            case CS_ERR_VERSION:
                printf(" Unsupported version (bindings)\n");
                break;
            case CS_ERR_DIET:
                printf("Access irrelevant data in diet engine\n");  
                break;
            case CS_ERR_SKIPDATA: 
                printf("Access irrelevant data for data instruction in SKIPDATA mode\n");
                break;
            case CS_ERR_X86_ATT:
                printf("X86 AT&T syntax is unsupported (opt-out at compile time)\n");
                break;
            case CS_ERR_X86_INTEL:
                printf("X86 Intel syntax is unsupported (opt-out at compile time)\n");
                break;
            default: 
                printf("ERROR no: %d\n", err_);
        }
    }
    if (count <= 0) {
        printf("callstack_instr plugin: %s: no disasm result for TB %p\n", __FUNCTION__, (void*)(uintptr_t)pc);
        goto done2;
    }

    for (end = insn + count - 1; end >= insn; end--) {
        if (!cs_insn_group(handle, end, CS_GRP_INVALID)) {
            break;
        }
    }
    if (end < insn) {
        printf("callstack_instr plugin: %s:No available instruction disasembled\n", __FUNCTION__);
        goto done;
    }

    if (pc != insn->address){
        printf("callstack_instr plugin: block address is not equal to its first intruction's address!!!\n");
        exit(-1);
    }

    if (cs_insn_group(handle, end, CS_GRP_CALL)) {
        res = INSTR_CALL;
    } else if (cs_insn_group(handle, end, CS_GRP_RET)) {
        res = INSTR_RET;
    } else if (cs_insn_group(handle, end, CS_GRP_INT)){
        res = INSTR_INT;
        // printf("%s: detect an interrupt\n", __FUNCTION__);
    } else if (cs_insn_group(handle, end, CS_GRP_IRET)){
        res = INSTR_IRET;
        // printf("%s: detect an interrupt return\n", __FUNCTION__);
    } else {
        res = INSTR_UNKNOWN;
    }

done:
    cs_free(insn, count);
done2:
    free(buf);
    return res;
}

int after_block_translate(CPUState *cpu, TranslationBlock *tb) {
    
    if (!init_capstone_done) init_capstone(cpu);

    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    call_cache[tb->pc] = disas_block(env, tb->pc, tb->size);

    // printf("%s: callstack_instr plugin: disas a block.\n", __FUNCTION__);

    return 1;
}

int before_block_exec(CPUState *cpu, TranslationBlock *tb) {
    // printf("callstack_instr plugin: %s:\n", __FUNCTION__);
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    std::vector<stack_entry> &v = callstacks[get_stackid(env)];
    std::vector<target_ulong> &w = function_stacks[get_stackid(env)];
    if (v.empty()) return 1;

    // Search up to 10 down
    // ==> Lele: search up to 500 down
    int depth = 0;
    bool found_ret = false;
    for (int i = v.size()-1; i > ((int)(v.size()-500)) && i >= 0; i--) {
        depth ++;
        if (tb->pc == v[i].pc) {
            // printf("%s: Matched at depth %d\n",__FUNCTION__, (int) v.size()-i);
            //v.erase(v.begin()+i, v.end());

            // ret to address is the next ip of last call instruction, which is stored in callstack
            // function_stacks stored all call to function addresses.
            // for each function addr w[i], corresponding a return address v[i] in the stack.
            if(!has_ret_after_block){
                printf("callstack_instr:(%s): WARNING: no ret instruction after previous block, but here detects a ret, tb->pc: 0x" TARGET_FMT_lx "\n",
                    __FUNCTION__, tb->pc);
            }
            PPP_RUN_CB(on_ret, cpu, w[i]);
            PPP_RUN_CB(on_ret2, cpu, tb, w[i], depth);
            v.erase(v.begin()+i, v.end());
            w.erase(w.begin()+i, w.end());
            found_ret = true;
            break;
        }
    }

    //TO detect an important corner case:
    // program will call himself, or another function, using 'ret' instruction:
    //  - it first manipulate stack, appending the callee address on top of stack
    //  - then by 'ret' instruction, it call the callee.
    //  
    // in this case, we will have the possibility to miss a function call
    // But we currently don't deal with it.

    if(found_ret = false){
        // more check for possible missing ret;
        if (has_ret_after_block){
            // got a ret instruction in previous block.
            printf("callstack_instr:(%s): WARNING: no ret detected according to call stack;but has a ret instruction in previous block\n",
                __FUNCTION__);
        }
    }
    return 0;
}

int after_block_exec(CPUState* cpu, TranslationBlock *tb) {
    // printf("callstack_instr plugin: %s: tb->pc: 0x" TARGET_FMT_lx "\n",__FUNCTION__, tb->pc);
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    instr_type tb_type = call_cache[tb->pc];
    // printf("callstack_instr plugin: %s: bb instr_type: %d\n", __FUNCTION__, (int)tb_type);
    
    if (tb_type == INSTR_CALL) {
        // printf("%s:%s: detect a call\n", __FILE__, __FUNCTION__);
        stack_entry se = {tb->pc+tb->size,tb_type};
        callstacks[get_stackid(env)].push_back(se);

        // Also track the function that gets called
        target_ulong pc, cs_base;
        uint32_t flags;
        // This retrieves the pc in an architecture-neutral way
        cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
        function_stacks[get_stackid(env)].push_back(pc);

        PPP_RUN_CB(on_call, cpu, pc);
        PPP_RUN_CB(on_call2, cpu, tb, pc);
    }
    // else if (tb_type == INSTR_INT) {
    //     printf("%s:%s: detect an interrupt\n", __FILE__, __FUNCTION__);
    //     stack_entry se = {tb->pc+tb->size,tb_type};
    //     callstacks[get_stackid(env)].push_back(se);

    //     // Also track the function that gets called
    //     target_ulong pc, cs_base;
    //     uint32_t flags;
    //     // This retrieves the pc in an architecture-neutral way
    //     cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    //     function_stacks[get_stackid(env)].push_back(pc);

    //     PPP_RUN_CB(on_call2, cpu, tb, pc);
    // }
    // TODO: we might need also detect INSTR_INT
    else if (tb_type == INSTR_RET) {
        //printf("Just executed a RET in TB " TARGET_FMT_lx "\n", tb->pc);
        //if (next) printf("Next TB: " TARGET_FMT_lx "\n", next->pc);
        has_ret_after_block = true;
    }

    return 1;
}

// Public interface implementation
int get_callers(target_ulong callers[], int n, CPUState* cpu) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    std::vector<stack_entry> &v = callstacks[get_stackid(env)];
    auto rit = v.rbegin();
    int i = 0;
    for (/*no init*/; rit != v.rend() && i < n; ++rit, ++i) {
        callers[i] = rit->pc;
    }
    return i;
}


#define CALLSTACK_MAX_SIZE 16
// writes an entry to the pandalog with callstack info (and instr count and pc)
Panda__CallStack *pandalog_callstack_create() {
    assert (pandalog);
    CPUState *cpu = first_cpu;
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    uint32_t n = 0;
    std::vector<stack_entry> &v = callstacks[get_stackid(env)];
    auto rit = v.rbegin();
    for (/*no init*/; rit != v.rend() && n < CALLSTACK_MAX_SIZE; ++rit) {
        n ++;
    }
    Panda__CallStack *cs = (Panda__CallStack *) malloc (sizeof(Panda__CallStack));
    *cs = PANDA__CALL_STACK__INIT;
    cs->n_addr = n;
    cs->addr = (uint64_t *) malloc (sizeof(uint64_t) * n);
    v = callstacks[get_stackid(env)];
    rit = v.rbegin();
    uint32_t i=0;
    for (/*no init*/; rit != v.rend() && n < CALLSTACK_MAX_SIZE; ++rit, ++i) {
        cs->addr[i] = rit->pc;
    }
    return cs;
}


void pandalog_callstack_free(Panda__CallStack *cs) {
    free(cs->addr);
    free(cs);
}


int get_functions(target_ulong functions[], int n, CPUState* cpu) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    std::vector<target_ulong> &v = function_stacks[get_stackid(env)];
    if (v.empty()) {
        return 0;
    }
    auto rit = v.rbegin();
    int i = 0;
    for (/*no init*/; rit != v.rend() && i < n; ++rit, ++i) {
        functions[i] = *rit;
    }
    return i;
}

void get_prog_point(CPUState* cpu, prog_point *p) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    if (!p) return;

    // Get address space identifier
    target_ulong asid = panda_current_asid(ENV_GET_CPU(env));
    // Lump all kernel-mode CR3s together

    if(!in_kernelspace(env))
        p->cr3 = asid;

    // Try to get the caller
    int n_callers = 0;
    n_callers = get_callers(&p->caller, 1, cpu);

    if (n_callers == 0) {
#ifdef TARGET_I386
        // fall back to EBP on x86
        int word_size = (env->hflags & HF_LMA_MASK) ? 8 : 4;
        panda_virtual_memory_rw(cpu, env->regs[R_EBP]+word_size, (uint8_t *)&p->caller, word_size, 0);
#endif
#ifdef TARGET_ARM
        p->caller = env->regs[14]; // LR
#endif

    }

    p->pc = cpu->panda_guest_pc;
}

int get_capstone_handle(CPUArchState* env, csh *handle_ptr){

#if defined(TARGET_I386)
    *handle_ptr = (env->hflags & HF_LMA_MASK) ? cs_handle_64 : cs_handle_32;
#elif defined(TARGET_ARM)
    *handle_ptr = cs_handle_32;

    if (env->thumb){
        if (cs_option(*handle_ptr, CS_OPT_MODE, CS_MODE_THUMB) != CS_ERR_OK){
            printf("ERROR cs_option ARM thumb\n");
            return -1;
        }
    }
    else {
        if (cs_option(*handle_ptr, CS_OPT_MODE, CS_MODE_ARM) != CS_ERR_OK){
            printf("ERROR cs_option ARM ARM\n");
            return -1;
        }
    }

#elif defined(TARGET_PPC)
    *handle_ptr = cs_handle_32;
#endif

    return 0;
}


bool init_plugin(void *self) {

// #if defined(TARGET_I386)
//     if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
// #if defined(TARGET_X86_64)
//     if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle_64) != CS_ERR_OK)
// #endif
// #elif defined(TARGET_ARM)
//     if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cs_handle_32) != CS_ERR_OK)
// #elif defined(TARGET_PPC)
//     if (cs_open(CS_ARCH_PPC, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
// #endif
//         return false;

//     // Need details in capstone to have instruction groupings
//     // cs_option(cs_handle_32, CS_OPT_DETAIL, CS_OPT_ON);

//     if (cs_option(cs_handle_32, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK){
//         printf("ERROR cs_option 32 bit\n");
//         return false;
//     }
// #if defined(TARGET_X86_64)
//     // cs_option(cs_handle_64, CS_OPT_DETAIL, CS_OPT_ON);
//     if (cs_option(cs_handle_64, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK){
//             printf("ERROR cs_optin for x86_64\n");
//             return false;
//     }
// #endif

    panda_cb pcb;

    panda_enable_memcb();
    panda_enable_precise_pc();

    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
    pcb.after_block_exec = after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) {
}
