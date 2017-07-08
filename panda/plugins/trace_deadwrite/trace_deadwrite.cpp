/* PANDABEGINCOMMENT
 * 
Authors:
    Lele Ma               lelema.zh@gmail.com

This plugin traces deadwrites, and print them to file 
    - mem_callback() called every time a memory access.
        inside this function, a prog_point is got from the plugin of callstack_instr plugin
    - prog_point:  3-tuple: 
        target_ulong caller;//
        target_ulong pc;    //
        target_ulong cr3;   //
    - deadspy: add define of 'CONTINUOUS_DEADINFO', refer this branch of deadspy code as the base
    - deadspy: store 3-tuple map of deadwrites <dead context, killing context, frequency>
        -- port "DeadMap" from deadspy.cpp; to store 3-tuple map of deadwrites <dead context, killing context, frequency> as <hashValue, frequency>, where hashValue = (dead_context_offset<<32 | killing_context_offset)
            - add def of "DeadMap", 'gPreAllocatedContextBuffer', 
            - init gPreAllocatedContextBuffer

    - deadspy: Context Tree
        --structs from deadspy: 
            ContextNode
            MergedDeadInfo, 
            DeadInfoForPresentation,
            TraceNode,-> BlockNode
            DeadInfo,
            include 'google sparse hash map'


    - deadspy: init_deadspy() function ported from deadspy:InitDeadSpy()
    - deadspy: last step report_deadspy()
    - deadspy: shadow mem:
        - GetOrCreateShadowBaseAddress()
        - GetShadowBaseAddress()

    - deadspy: detect deadwrite and maintain CCT in Instruction Level :
      
      ===================
      In instrument trace level. 
      ===================
      PIN Deadspy uses this to find and store function call stack. But don't use this in panda:
      Reason: Panda could get call stacks by intrumenting in the instruction level by plugin 'callstack_instr'
        - InstrumentTrace()
        - InstrumentTraceEntry() : instrumentBeforeBlockExe : get function info
        - (), 
            - InstructionContributionOfBBL1Byte()

      ===================
      Instrument Instruction Level. 
      ===================
      PIN Deadspy use this to detect deadwrite, without giving the CCT. 
      Here, we will use this both to 
        - detect deadwrite and
        - maintain the CCT (only when a func call/ret is detected, we update cct.)
        In order to do this: we need the following functions/structures to be adapted from PIN Deadspy:

        - InitContextTree() in initilize the plugin.

        - Port Instruction() from Deadspy to mem_callback()
          Instruction:functions  ==> mem_callback: functions

            - detect R/W with size using Pin ==> mem r/w with size in Panda
              in function mem_callback
                -Do1ByteCount()...DoLargeByteCount()

            - dynamically generate call context tree:
                - ManageCallingContext()

            - recording R/W to shadow mem:
                - Record1ByteMemRead(), 2, 4, 8, 10, 16, RecordLargeMemRead()
                - Record2ByteMemRead(), 2, 4, 8, 10, 16, RecordLargeMemWrite()

            - print deadinfo:
                - ImageUnload() -> ExtractDeadMap
                - Fini()
        - Update gCurrentTraceIpVector, the array store all IPs for mem WRITE under the current ContextNode
            - on each new mem W detected, 
}

Jun 24: in order to avoid the situation:
    // where for same basic block, execution in different times could have different write pcs.   
    // Solution 1 (current): tracking whether we have stored a write pc in the ShadowMap for that block.
    //  - use a subMap for each basic block, gBlockShadowIPtoSlot[tb->pc]=< target_ulong IP, int slot >. If tb->pc has pc has its IP stored in ShadowMap, we set the int value as positive number as its slot index..
    //  - for gTraceNode->childIPs, whenever we need to report the deadInfo with the IP's slot index, we get the slot from gBlockShadowIPtoSlot
    //  
    // Solution 2 (not implemented yet, abandoned.) : inside each basic block, assign a static slot for every PC.
    //  - only one slot will be assigned for one pc;
    //  - every different basic block has it's own map;
    //  - slot can be assigned at the time we found the basic block: either after translation, or before execution, or during execution, but not after execution.; 
    //  - slots should be checked after execution;
    //  - In order to get the slot number quickly by its pc, we add a subMap for each basic block: gBlockShadowIPtoSlot[tb->pc] = < IP, slot >


    ==========================

TODO:

    debug modes:
        - no multi thread, with IP and CCT enabled
        - multi thread enable.
    debug stages:
        - mem_callback() one call iteration.
        - report dead
        - print dead

 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

#include "trace_deadwrite.h"

// ######################################################
// ######################################################
// ########## Part 2.1: Function Definitions ############
// ######################################################
// ######################################################

/*
inline void  print_proc_info(OsiProc *proc)

*/

inline void print_proc_info(OsiProc *proc){

    printf("\tproc name: %s,", proc->name);

    // if(proc->pid){
        printf("\tpid: " TARGET_FMT_lu, proc->pid);
    // }else{
    //     printf("\tpid: N/A");
    // }

    // if(proc->ppid){
        printf("\tppid: " TARGET_FMT_lu , proc->ppid);
    // }else{
        // printf("\tppid: N/A");
    // }

    // if(proc->asid){
        printf("\tp->asid: 0x" TARGET_FMT_lx , proc->asid);
    // }else{
    //     printf("\tp->asid: N/A");
    // }

    // if(proc->offset){
        printf("\t\tp->offset: 0x" TARGET_FMT_lx , proc->offset);
    // }else{
    //     printf("\tp->offset: N/A");
    // }

    if (proc->pages && proc->pages->start && proc->pages->len ){
        printf("\t page start: 0x" TARGET_FMT_lx ", page len: " TARGET_FMT_lu " \n",   
            proc->pages->start, proc->pages->len);
    }

    printf("\n\n");
}


/*
 is_target_process_running
    - return true if the target process is running at this time point the function is called.

    - could distinguish the target process by process name or asid.

    - return value: true if target proc is recognised.

    - return para: 
        - judge_by_struct: flag the judge metric. true: judge by OsiProc; false: judge by asid.
        - asid_ret: the cpu->cr3 asid. always valid.
        - OsiProc *p_ret: store the pointer of OsiProc, only valid when judge_by_struct is true.

*/

inline bool is_target_process_running(CPUState *cpu, bool *judge_by_struct, target_ulong *asid_ret, OsiProc **p_ret){

    bool is_target = false;

    OsiProc *p = get_current_running_process(cpu);
    *p_ret = p;

    target_ulong asid = panda_current_asid(cpu);
    *asid_ret = asid;

    if (p==0){
        // process info not available
        // use asid to distinguish, lele: should be abandoned.
        // printf("\t judge by asid: 0x" TARGET_FMT_lx ", target: 0x" TARGET_FMT_lx "\n",asid, gTargetAsid);
        *judge_by_struct = false;

        // if (asid == gTargetAsid || asid == gTargetAsid_struct){
        if (asid == gTargetAsid ){
            is_target = true;
        }else{
            gIgnoredASIDs.insert(asid);
            is_target = false;
        }
    }else{
        // printf("\t judge by name: %s, or struct_asid: 0x" TARGET_FMT_lx ", target: 0x" TARGET_FMT_lx "\n", p->name, p->asid, gTargetAsid_struct);
        // printf("\t judge by struct name: %s\n", p->name);
        *judge_by_struct = true;
        std::string curProc(p->name);
        // if (curProc == gProcToMonitor || p->asid == gTargetAsid_struct){
        if (curProc == gProcToMonitor){
            // found the target proc
            // update the target asid.
            gTargetAsid = panda_current_asid(cpu);
            gTargetAsid_struct = p->asid;
            is_target = true;

        }else{
            // keeping track of both p->asid and cpu->cr3
            gIgnoredASIDs.insert(p->asid);
            gIgnoredASIDs.insert(panda_current_asid(cpu));
            is_target = false;
        }
    }

    if (is_target && !gProcFound){
        printf("\t%s: WARNING: target process set to be running here but not found in 'handle_proc_change'\n", __FUNCTION__);
    }
    return is_target;
}

/*  

*/
OsiProc * get_current_running_process(CPUState *cpu){
    
    OsiProc *p=0;
    // target_ulong asid;

    // if (panda_in_kernel(cpu)) { // Lele: why have to be in kernel????

        // printf("%s: calling get_current_process\n", __FUNCTION__);
        p = get_current_process(cpu);

        // printf("%s: calling get_current_process, done.\n", __FUNCTION__);
        //some sanity checks on what we think the current process is
        // this means we didnt find current task
        if (!p){
            // printf("%s: no process info get, now return 0\n", __FUNCTION__);
            return 0;
        }else{
                
            if (p->offset == 0 || p->name == 0 || ((int) p->pid) == -1) {
                // printf("%s: ERROR get current proc, lacking offset/name/pid\n", __FUNCTION__);
                // exit(-1);
                return 0;
            }

            // printf("%s: good, has offset/name/pid.\n", __FUNCTION__);
            uint32_t n = strnlen(p->name, 32);
            // name is one char?
            if (n<2) {
                printf("%s: ERROR get current proc name(length < 2): %s\n", __FUNCTION__, p->name);
                // exit(-1);
                return 0;
            }
            uint32_t np = 0;
            for (uint32_t i=0; i<n; i++) {
                np += (isprint(p->name[i]) != 0);
            }
            // name doesnt consist of solely printable characters
            //        printf ("np=%d n=%d\n", np, n);
            if (np != n) {
                // printf("%s: name doesnt consist of solely printable characters\n", __FUNCTION__);
                //printf ("np=%d n=%d\n", np, n);
                // exit(-1);
                return 0;
            }
            // asid = p->asid;
            ProcID p_ = {p};
            if (gRunningProcs.count(p_)==0){
                gRunningProcs.insert(p_);
            }
            // check whether a new proc name.
            checkNewProc(std::string(p->name));
        }
    // }

    return p;

}


/* panda_current_asid_proc_struct
    - use process's task struct to get the asid value.
    - if cannot get task struct, use cpu->cr3 by panda_current_asid()
*/

target_ulong panda_current_asid_proc_struct(CPUState *cpu){

    target_ulong asid;
    

    // the asid got from cpu->cr3 is usually different than the asid got from the task struct.
    // therefore, we use task struct to get the asid in the first priority.
    // - also use cpu->cr3 if we failed to get it from task struct.

    // printf("Now in %s\n", __FUNCTION__);
    OsiProc *p;

    p = get_current_running_process(cpu);

    if (p != 0){
        asid = p-> asid;

    }else{
        // printf("%s: WARNING: p is null, using cpu->cr3 to get asid\n", __FUNCTION__);
        asid = panda_current_asid(cpu);
    }
        // printf("%s: done.\n", __FUNCTION__);
        return asid;
}


#ifndef MULTI_THREADED
// The following functions accummulates the number of bytes written in this basic block for the calling thread categorized by the write size. 

inline VOID InstructionContributionOfBBL1Byte(uint32_t count){
    g1ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL2Byte(uint32_t count){
    g2ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL4Byte(uint32_t count){
    g4ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL8Byte(uint32_t count){
    g8ByteWriteInstrCount += count;
    printf("%s:g8ByteWriteInstrCount+=count\n",__FUNCTION__);
}
inline VOID InstructionContributionOfBBL10Byte(uint32_t count){
    g16ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL16Byte(uint32_t count){
    g16ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBLLargeByte(uint32_t count){
    gLargeByteWriteInstrCount += count;
}
#else  // ifndef MULTI_THREADED

// The following functions accummulates the number of bytes written in this basic block categorized by the write size. 

inline VOID InstructionContributionOfBBL1Byte(uint32_t count){    
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt1ByteWriteInstrCount  +=  count;
}
inline VOID InstructionContributionOfBBL2Byte(uint32_t count){
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt2ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL4Byte(uint32_t count){
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt4ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL8Byte(uint32_t count){
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt8ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL10Byte(uint32_t count){
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt10ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL16Byte(uint32_t count){
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt16ByteWriteInstrCount +=  count;
}
inline VOID InstructionContributionOfBBLLargeByte(uint32_t count){
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mtLargeByteWriteInstrCount += count;
}

#endif // end MULTI_THREADED

#ifdef CONTINUOUS_DEADINFO
// TODO - support MT. I dont think this needs to be thread safe since PIN guarantees that.
inline void ** GetNextIPVecBuffer(uint32_t size){
    void ** ret = gPreAllocatedContextBuffer + gCurPreAllocatedContextBufferIndex;
    gCurPreAllocatedContextBufferIndex += size;
    assert( gCurPreAllocatedContextBufferIndex  < (PRE_ALLOCATED_BUFFER_SIZE)/(sizeof(void **)));
    return ret;
}
// // Lele: for a gCurrentTraceBlock, the size of its childIPs could be changing during the execution.
// // this function can adjust the size of IPVecBuffer that has already allocated to the gCurrentTraceBlock previously.
//  -->> Lele: not in use because it might overlap with the buffer of other TraceNodes'
//
// inline void ** AdjustIPVecBuffer(BlockNode ** currentTraceBlock, uint32_t size){
//     void ** ret = (void **) currentTraceBlock;
//     uint64_t oldIndex = (uint64_t) (ret - gPreAllocatedContextBuffer);
//     gCurPreAllocatedContextBufferIndex = oldIndex + size;
//     assert( gCurPreAllocatedContextBufferIndex  < (PRE_ALLOCATED_BUFFER_SIZE)/(sizeof(void **)));
//     return ret;
// }
#endif //end CONTINUOUS_DEADINFO



// #ifdef IP_AND_CCT

//     // Analysis routine called on entering a function (found in symbol table only)
//     //inline VOID UpdateDataOnFunctionEntry(ADDRINT currentIp){
//     //LELE: moved to before_block_exec
//     inline VOID UpdateDataOnFunctionEntry(CPUState *cpu, TranslationBlock *tb){

//         // if I enter here due to a tail-call, then we will make it a child under the parent context node
//         // if (!gInitiatedCall){
//         //     printf("a tailer call?\n");
//         //     gCurrentContext = gCurrentContext->parent;
//         // } else {

//         if (gInitiatedCall){
//             // normal function call, so unset gInitiatedCall
//             // printf("%s:get a new function call !\n", __FUNCTION__);
//             gInitiatedCall = false;
//             // Let GoDownCallChain do the work needed to setup pointers for child nodes.
//             GoDownCallChain(cpu,tb);

//             //TODO: check if tb->pc is equal with currentIp
//             printf("%s: go down to context: 0x" TARGET_FMT_lx"\n", __FUNCTION__, gCurrentContext->address);
//             // printf("%s: go down to BasicBlock: 0x" TARGET_FMT_lx"\n", __FUNCTION__, tb->pc);
        
//         }else{
//             printf("ERROR: call function entry, but call flag is not true\n");
//             exit(-1);
//         }


//     }

// #endif //end IP_AND_CCT

// MT
#ifndef MULTI_THREADED

// Analysis routine called on function entry. 
// If the target IP is a child, make it gCurrentContext, else add one under gCurrentContext and point gCurrentContext to the newly added

VOID GoDownCallChain(CPUState *cpu, target_ulong callee){
// VOID GoDownCallChain(CPUState *cpu, TranslationBlock *tb){
    // printf("%s: go down chain, tb->pc = 0x" TARGET_FMT_lx "\n",__FUNCTION__, tb->pc);
    // target_ulong callee=tb->pc;
    // if( ( gContextIter = (gCurrentContext->childContexts).find(callee)) != gCurrentContext->childContexts.end()) {
    if ( (gCurrentContext->childContexts).count(callee) != 0){
        // printf("%s: down to existed context node; bb addr: 0x" TARGET_FMT_lx "\n", __FUNCTION__, callee);
        // gCurrentContext = gContextIter->second;
        gCurrentContext = (gCurrentContext->childContexts)[callee];
    } else {
        ContextNode * newChild =  new ContextNode();
        newChild->parent = gCurrentContext;
        newChild->address = callee;
        (gCurrentContext->childContexts)[callee] = newChild;
        gCurrentContext = newChild;
        printf("%s: new context node; func addr: 0x" TARGET_FMT_lx "\n",__FUNCTION__, callee);
    }
}

// Analysis routine called on function return. 
// Point gCurrentContext to its parent, if we reach the root, set gInitiatedCall.//lele: why?

inline VOID GoUpCallChain(CPUState *cpu, TranslationBlock *dst_tb,  target_ulong from_func, int depth){
// #ifdef IP_AND_CCT
    //assert(gCurrentContext->parent && "NULL PARENT CTXT");
    if (gCurrentContext == gRootContext){
        printf("%s: WARNING: RootContext got a return, don't change context node.\n",__FUNCTION__);
        return;
    }
    // else if (gCurrentContext->parent == gRootContext) {
    //     // gInitiatedCall = true;//lele: why?
    //     printf("lele: ret to root context node\n");
    // }
    // go up 'depth' nodes.
    int i;
    for (i = 0; i< depth && gCurrentContext != gRootContext; i++){
        gCurrentContext = gCurrentContext -> parent;
    }
    if (gCurrentContext == gRootContext){
        printf("%s: go up %d call path and reached root\n", __FUNCTION__, i);
    }
    // call go down call chain to exec the new basic block: dst_tb.
    GoDownCallChain(cpu, dst_tb->pc);
    // RET & CALL end a trace hence the target should trigger a new trace entry for us ... pray pray.
    
// #else    // no IP_AND_CCT
//     gCurrentContext = gCurrentContext->parent;
// #endif    //end IP_AND_CCT

    // printf("%s: up to parent context: bb addr: 0x" TARGET_FMT_lx "\n",__FUNCTION__, gCurrentContext->address);
    
}
#else // MULTI_THREADED

// Analysis routine called on function entry. 
// If the target IP is a child, make it gContextTreeVector[pinTID].currentContext, else add one under gContextTreeVector[pinTID].currentContext and point gContextTreeVector[pinTID].currentContext to the newly added

// VOID GoDownCallChain(ADDRINT callee){
VOID GoDownCallChain(CPUState *cpu, TranslationBlock *tb){

    printf("%s: multithread: tb->pc=0x" TARGET_FMT_lx "\n", __FUNCTION__, tb->pc);
    target_ulong callee= tb->pc;

    // sparse_hash_map<ADDRINT, ContextNode *>::iterator contextIter;
    // uint32_t pinTID = (uint32_t)PIN_ThreadId();
    
    // if( ( contextIter = (gContextTreeVector[pinTID].currentContext->childContexts).find(callee)) != gContextTreeVector[pinTID].currentContext->childContexts.end()) {
    //     gContextTreeVector[pinTID].currentContext = contextIter->second;
    // } else {
    //     ContextNode * newChild =  new ContextNode();
    //     newChild->parent = gContextTreeVector[pinTID].currentContext;
    //     newChild->address = callee;
    //     gContextTreeVector[pinTID].currentContext->childContexts[callee] = newChild;
    //     gContextTreeVector[pinTID].currentContext = newChild;
    // }
}

// Analysis routine called on function return. 
// Point gContextTreeVector[pinTID].currentContext to its parent.

inline VOID GoUpCallChain(){
    // uint32_t pinTID = (uint32_t)PIN_ThreadId();
    // gContextTreeVector[pinTID].currentContext = gContextTreeVector[pinTID].currentContext->parent;
}
#endif //end ifndef MULTI_THREADED



// Instrumentation added at function call/ret sites


//   inline VOID ManageCallingContext2(CPUState *cpu, TranslationBlock *tb){
// #ifdef TESTING_BYTES
//     return; // no CCT
// #endif // end TESTING_BYTES
    
//     // manage context
//     // Refer: ManageCallingContext(ADDRINT)

//     // if(INS_IsProcedureCall(ins) ) {
//     if(gInitiatedCall || gInitiatedINT) {    
//         GoDownCallChain(cpu, tb); 
//     }else if(gInitiatedRet || gInitiatedIRET){
//         GoUpCallChain();
//     }

//     printf("%s: done manage context for one memory operating instruction\n\n", __FUNCTION__);
//     // return ;
//   }
  
// inline VOID ManageCallingContext(CallStack *fstack){
// #ifdef TESTING_BYTES
// 	return; // no CCT
// #endif // end TESTING_BYTES
    
//     // manage context
//     // lele: need to write new functions and methods to manage context
//     // generally: 
//     //  1, we use context node and ip slots solution, don't use any trace nodes.(But during adaption, we use only on BlockNode with ContextNode's IP as key)
//     //  This would reduce lots of overhead compared to Trace solution in PIN Deadspy. At least there is only one array store write IPs instead of many Trace Nodes.
//     //  2, we need to detect current context change by prog_point info and update our CCT by goDown/goUp;
//     //
//     //lele: check and detect a function call boundaries by comparing the CallStack with the current call CCT.
//     // if context node of currentIp is the last one of the caller stack. No func call is initiated.
//     // if context node of currentIp is the second last of the caller stack. New func call has been done.
//     // Otherwise, if current context node doesn't exists in the caller stack. Distinguish it by the last one of the call stack.
//     //  - a ret : last caller is the parent of current context node.
//     //  - a new func call : last caller is not the parent of current context node.

//     // if an function call, continue with trace entry method from PIN deadspy, otherwise, return.


//     //printf("step 1/3: detect whether in new func\n");
//     //#################################################
//     //################# step 1/3, detect whether in ####
//     //  - current function, iff curContextNode is the same with last of caller stack, or 
//     //                         caller stack size is zero and curContextNode is the same with root of ContextNode.
//     //      - just return in this case, do nothing to context nodes.
//     //
//     //  - a ret function, iff curContextNode doesn't exists in call stack but last caller is the parent of the current context node.
//     //      -call goUpCallChain to update curContextNode.
//     //
//     //  - a new function call, iff curContextNode is the same with second last of caller stack, or 
//     //                              curContextNode is not in the call stack and laster caller is not the parent of current context node(WRONG/IMP CASE).
//     //      -call goDownCallChain to create new ContextNode
//     //
//     // we don't detect function call directly. 
//     // we find a new function by comparing the last function in call stack with the current function.
//     gInitiatedCall = false;
//     gInitiatedRet = false;

//     ADDRINT curContextIp = gCurrentContext->address;
//     ADDRINT parContextIp;

//     // ADDRINT currentIp = fstack->pc;
//     ADDRINT callerIp, callerCallerIp;

    
//     printf("curContextIp: " TARGET_FMT_lx "\n", curContextIp);
//     if (fstack->n < 0){
//             printf("ERROR: get neg callers.\n");
//             exit(-1);

//     }else if (fstack->n == 0){
//         // no callers, must be in current func
//         //printf("%s: get 0 callers\n", __FUNCTION__);
//         if (gCurrentContext != gRootContext  && gCurrentContext-> parent != gRootContext){
//             //when no func, gCurrentContext or its parent must be equal with gRootContext
//             printf("ERROR: when no func, gCurrentContext must point to gRootContext!!!\n");
//             exit(-1);
//         }else if (gCurrentContext-> parent == gRootContext){
//             gInitiatedRet = true;
//             printf("return to no func level!!\n");
//         //}else{
//             //printf("GOOD: init, no function yet!\n");
//         }
//         callerIp=gCurrentCallerIp;

//         //keep gInitatedCall to be false in this case;
//     }else {
//         // call stack has at least one element, could be three cases:
//         // - current func
//         // - a new func
//         // - a ret 

//         // get last caller's ip
//         callerIp = fstack->callers[CALLERS_LAST];
//         printf("get callerIp on stack: " TARGET_FMT_lx "\n", callerIp);
//         gCurrentCallerIp= callerIp;
//         // callerIp = fstack->callers[0];
//         if(fstack->n == 1){
//             printf("first level function ever!!!\n");
//         }

//         // detect in current func by compare last caller with current Context.
//         if (curContextIp == callerIp){
//             //no new call if last caller is the same with current Context.
//             gInitiatedCall = false;
//             printf("no new call, do nothing.\n");
//             return;
//         }else{
//             // now curContextIp is not last caller, two cases:
//             // a ret, or a new func call
//             if(fstack->n == 1){
//                 //in first level function; if gCurrentContext pointed to root, then should be in new function
//                 if (gCurrentContext == gRootContext){
//                     printf("Entered first level function from root!\n");
//                     // callerIp is first level's func; move currentContext to this func;
//                     // create one child of RootContext
//                     gInitiatedCall = true;
//                 }else{
//                     printf("gCurrentContext is not root; instruction is in first level func; so not new func. Do nothing.\n");
//                 }
//             }else{
//                 //in other level functions:
//                 // - a new func call, curContextNode is the second last of call stack, or
//                 //                    curContextNode is not the second last of call stack, neither it's parent is the last one in call stack, but in the second last is it's parent.
//                 // - a ret, curContextNode is not the second last of call stack, but it's parent is the last in call stack.
//                 callerCallerIp = fstack->callers[CALLERS_SECOND_LAST];
//                 if (curContextIp == callerCallerIp){
//                     // current Context is the second last of call stack, enter a new func.
//                     // curContext will become the parent of this new func.
//                     // first detect whether this func is already a children of currentContext. if not, create one.
//                     // set cur context with callerIp.
//                     gInitiatedCall=true;
//                     printf("curContext is equal to caller of the caller; so new call detected\n");
//                 }else {
//                     // current Context is neither the last nor the second last in the call stack.
//                     // - a ret: current Context's parent is the last in call stack.
//                     // WRONG: current Context's parent is not the last in call stack.
//                     // //curContext is impossible to be root when there are more than one callers in stack.
//                     if (gCurrentContext == gRootContext){
//                         printf("ERROR: current context node should not be root context when there are >2 callers in stack. A new context should be created when there is 1 callers in stack.\n");
//                     }
//                     ContextNode * parContext = gCurrentContext->parent;
//                     // parContext is impossible to be root: parent context must be last in call stack, so should not be the root.
//                     // when parent of the cur context node is the root, it's in the first func, call stack is at most 2 callers where cur context is the second last in call stack.
//                     parContextIp = parContext->address;

//                     if(parContextIp == callerIp){
//                         gInitiatedRet = true;
//                         printf("parent ContextIp is equal to the caller Ip, a ret detected. \n");
//                     }else{
//                         printf("ERROR: callers>=2: current Context is neither the last nor the second last in the call stack, and current Context's parent is not the last in call stack.\n");
//                         exit(-1);
//                     }
//                 }
//             }

//         }
        
//     }

//     // ###################################################
//     // ################### step 2/3, #####################
//     // ###################################################
//     //  - create Context Node when new func call; 
//     //  - store IP to shadow pages
//     //  to simulate the PopulateIPReverseMapAndAccountTraceInstructions() on every new func call, which had store IPs for all 
//     //  Instructions
//     //  - reset slot to 0.
//     //  - add current pc as first instruction in ip

//     //printf("step 2/3: create Context Node when new func call\n");
    
//     ////////////////////////////////////
//     // InstrumentTrace(TRACE trace, void * f):
//     //   BBL bbl = TRACE_BblHead(trace);
//     //   INS ins = BBL_InsHead(bbl);
//     //   INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)InstrumentTraceEntry,IARG_INST_PTR,IARG_END);    
//     //   PopulateIPReverseMapAndAccountTraceInstructions(trace);

//     // // Does necessary work on a trace entry (called during runtime)
//     // // 1. If landed here due to function call, then go down in CCT.
//     // // 2. Look up the current trace under the CCT node creating new if if needed.
//     // // 3. Update global iterators and curXXXX pointers.

//     // inline void InstrumentTraceEntry(ADDRINT currentIp){
        
//     // if landed due to function call, create a child context node

//     if(gInitiatedCall){
//         // gInitatedCall = true, means this mem R/W instruction is inside a new function call
//         // So, we need to:
//         //  - update the CCT with a new Context Node and 
//         //  - update corresponding array slot index to store the new IP with mem W (no read)
//         //
//         // a new function call is on the top of call stack.
//         printf("gInitiatedCall=true\n");

//         UpdateDataOnFunctionEntry(callerIp); // it will reset   gInitiatedCall  

//         // MOVED to block assemb.
//         // printf("setup according to PopulateIPReverseMapAndAccountTraceInstructions() in deadspy\n");
//         // //uint32_t traceSize = TRACE_Size(trace);    
//         // uint32_t traceSize = 0x80;    //lele: TODO: determine the size of function
     
//         // ADDRINT * ipShadow = (ADDRINT * )malloc( (1 + traceSize) * sizeof(ADDRINT)); // +1 to hold the number of slots as a metadata
//         // ADDRINT  traceAddr = callerIp;
//         // uint32_t slot = 0;
    
//         // gCurrentSlot = slot;
    
//         // // give space to account for nSlots which we record later once we know nWrites
//         // ADDRINT * pNumWrites = ipShadow;
//         // ipShadow ++;
//         // gBlockShadowMap[traceAddr] = ipShadow ;

//         //  // Record the number of child write IPs i.e., number of "slots"
//         // *pNumWrites = slot;

//     }else if(gInitiatedRet){
//         printf("get a ret; call GoUpCallChain...\n");
//         // Let GoDownCallChain do the work needed to setup pointers for child nodes.
//         GoUpCallChain();
//     }else if (gInitiatedCall && gInitiatedRet){
//         printf("ERROR: cant ret and call at same time\n");
//         exit(-1);
//     // }else{
//     //     printf("no new call, no ret.\n");
//     }
    
//     //#######################################################
//     // ######################## setp 3/3, #################
//     // update currentIp slots for curContextNode. necessary here!
//     // lele: we adapt the name of "Trace" to store the slots. Might be improved by using a single BlockNode instead of a map with only one BlockNode.

//     // Check if a trace node with currentIp already exists under this context node
    
//     //printf("step 3/3, update currentIp slots for curContextNode. necessary here!\n");
//     // Check if a trace node with currentIp already exists under this context node    
          
//     //printf("callerIp: " TARGET_FMT_lx "\n", callerIp);
//     if( (gTraceIter = (gCurrentContext->childBlocks).find(callerIp)) != gCurrentContext->childBlocks.end()) {
//         // if tracenode is already exists
//         // set the current Trace to the new trace
//         // set the IpVector
//         //printf("Trace Node already exists\n");
//         gCurrentTraceBlock = gTraceIter->second;
//         gCurrentTraceIpVector = gCurrentTraceBlock->childIPs;
//         //lele: set slot index
//         // gCurrentSlot = gCurrentTraceBlock->nSlots;
//         // printf("Trace Node exists; set/get current slots:%u\n", gCurrentSlot);

//      } else {
//         //panda: if not in the current context node, this means in a new function and a new context node is created.
        
//         // Create new trace node and insert under the context node.
//         printf(__FUNCTION__);
//         printf(": Need to Create new Trace node.\n");

//         BlockNode * newChild = new BlockNode();
//         printf("BlockNode New Child Created\n");
//         printf("\tNew Child: set parent\n");
//         newChild->parent = gCurrentContext;
//         printf("\tNew Child: set address\n");
//         newChild->address = callerIp;
//         printf("get currentBlockShadowMap from gBlockShadowMap[callerIp]\n");
//     	target_ulong * currentBlockShadowMap = (target_ulong *) gBlockShadowMap[callerIp];
//         printf("get recordedSlots from currentBlockShadowMap[-1] %p\n", currentBlockShadowMap);
//         target_ulong recordedSlots = currentBlockShadowMap[-1]; // present one behind
//         if(recordedSlots){
//             printf("Record Slots: " TARGET_FMT_lx "\n", recordedSlots);
// #ifdef CONTINUOUS_DEADINFO
//             // if CONTINUOUS_DEADINFO is set, then all ip vecs come from a fixed 4GB buffer
//             printf("Continuous Info: GetNextIPVecBuffer...\n");
//             newChild->childIPs  = (BlockNode **)GetNextIPVecBuffer(recordedSlots);
// #else            //no CONTINUOUS_DEADINFO
//             printf("NON Continuous Info: malloc new BlockNode**\n");
//             newChild->childIPs = (BlockNode **) malloc( (recordedSlots) * sizeof(BlockNode **) );
// #endif //end CONTINUOUS_DEADINFO
//             newChild->nSlots = recordedSlots;
//             //std::cerr<<"\n***:"<<recordedSlots; 
//             for(uint32_t i = 0 ; i < recordedSlots ; i++) {
//                 newChild->childIPs[i] = newChild;
//             }
//         } else {
//             printf("No record slots read\n");
//             newChild->nSlots = 0;
//             newChild->childIPs = 0;            
//         }    
//         gCurrentContext->childBlocks[callerIp] = newChild;
//         gCurrentTraceBlock = newChild;
//         gCurrentTraceIpVector = gCurrentTraceBlock->childIPs;
//         //lele: set slot index
//         // gCurrentSlot = gCurrentTraceBlock->nSlots;
//     }    

// //     if(INS_IsProcedureCall(ins) ) {
// // #ifdef IP_AND_CCT
// //         INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) SetCallInitFlag,IARG_END);
// // #else        // no IP_AND_CCT        
// //         INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) GoDownCallChain, IARG_BRANCH_TARGET_ADDR, IARG_END);
// // #endif // end IP_AND_CCT        
// //     }else if(INS_IsRet(ins)){
// //         INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) GoUpCallChain, IARG_END);
// //     }
//     printf("%s: done manage context for one memory operating instruction\n\n", __FUNCTION__);
// }





//// MT
#ifndef MULTI_THREADED 

// Initialized the fields of the root node of all context trees
VOID InitContextTree(){
     
#ifdef IP_AND_CCT
    // MAX 10 context trees
    gContextTreeVector.reserve(CONTEXT_TREE_VECTOR_SIZE);
    for(uint8_t i = 0 ; i < CONTEXT_TREE_VECTOR_SIZE ; i++){
        ContextNode * rootNode = new ContextNode();
        rootNode->address = 0;
        rootNode->parent = 0;        
        gContextTreeVector[i].rootContext = rootNode;
        gContextTreeVector[i].currentContext = rootNode;


    }
    gCurrentContext = gContextTreeVector[0].rootContext;
    gRootContext = gContextTreeVector[0].rootContext;

    printf("initialize gBlockShadowMap and gBlockShadowIPtoSlot\n");
        //uint32_t traceSize = TRACE_Size(trace);    
    uint32_t traceSize = 0x0;    //lele: TODO: determine the size of function
    ADDRINT * ipShadow = (ADDRINT * )malloc( (2 + traceSize) * sizeof(ADDRINT)); // +1 to hold the number of slots as a metadata

    ADDRINT  traceAddr = 0;
    uint32_t slot = 0;
    
    // gCurrentSlot = slot;
    gCurrentCallerIp = 0x0;
    
// give space to account for nSlots which we record later once we know nWrites
    ADDRINT * pTraceSize = ipShadow;
    ipShadow ++;
    *pTraceSize = traceSize;

    ADDRINT * pNumWrites = ipShadow;
    ipShadow ++;
    // Record the number of child write IPs i.e., number of "slots"
    *pNumWrites = slot;

    gBlockShadowMap[traceAddr] = ipShadow ;

    //lele: gBlockShadowIPtoSlot;
    // printf("BUG HERE\n");
    // printf("%s: size of (std::tr1::unordered_map<ADDRINT, int>): %d\n", __FUNCTION__,(int)sizeof(std::tr1::unordered_map<ADDRINT, int >) );
    std::tr1::unordered_map<ADDRINT, int> * mapIps = 
        new std::tr1::unordered_map<ADDRINT, int>;
        //(std::tr1::unordered_map<ADDRINT, bool> *) malloc (sizeof(std::tr1::unordered_map<ADDRINT,bool>));
    printf("%s: shadowMapIps allocated.\n", __FUNCTION__);
    //(*mapIps).reserve(8);
    // (*mapIps)[traceAddr] = -1;

    // printf("%s: set shadowMapIps[traceAddr] to false, meaning the array of BB has no traceAddr as write IP yet.\n",__FUNCTION__);
    gBlockShadowIPtoSlot[traceAddr] = mapIps;




    printf("done initializing gBlockShadowMap and gBlockShadowIPtoSlot\n");
   
#else // no IP_AND_CCT
    gCurrentContext = gRootContext = new ContextNode();
    gRootContext->parent = 0;
    gRootContext->address = 0;
    
#endif // end IP_AND_CCT    
    
    // Init the  segv handler that may happen (due to PIN bug) when unwinding the stack during the printing   
    // Lele: cmt this with Panda. 
    // memset (&gSigAct, 0, sizeof(struct sigaction));
    // gSigAct.sa_handler = SegvHandler;
    // gSigAct.sa_flags = SA_NOMASK ;
    
}

#else // MULTI_THREADED

// Initialized the fields of the root node of all context trees
VOID InitContextTree(){
    // Multi threaded coded have a ContextTree per thread, my code assumes a max of 10 threads, for other values redefine CONTEXT_TREE_VECTOR_SIZE
    // We intialize all fields of the context tree which includes per thread stats
    
    
    // MAX 10 context trees
    gContextTreeVector.reserve(CONTEXT_TREE_VECTOR_SIZE);
    for(uint8_t i = 0 ; i < CONTEXT_TREE_VECTOR_SIZE ; i++){
        ContextNode * rootNode = new ContextNode();
        rootNode->address = 0;
        rootNode->parent = 0;        
        gContextTreeVector[i].rootContext = rootNode;
        gContextTreeVector[i].currentContext = rootNode;
        gContextTreeVector[i].mt1ByteWriteInstrCount = 0;
        gContextTreeVector[i].mt2ByteWriteInstrCount = 0;
        gContextTreeVector[i].mt4ByteWriteInstrCount = 0;
        gContextTreeVector[i].mt8ByteWriteInstrCount = 0;
        gContextTreeVector[i].mt10ByteWriteInstrCount = 0;
        gContextTreeVector[i].mt16ByteWriteInstrCount = 0;
        gContextTreeVector[i].mtLargeByteWriteInstrCount = 0;
        gContextTreeVector[i].mtLargeByteWriteByteCount = 0;
    }
    
    // Init the  segv handler that may happen (due to PIN bug) when unwinding the stack during the printing    
    // Lele: cmt this with Panda. 
    // memset (&gSigAct, 0, sizeof(struct sigaction));
    // gSigAct.sa_handler = SegvHandler;
    // gSigAct.sa_flags = SA_NOMASK ;
    
}

#endif // end MULTI_THREADED

// Given a address generated by the program, returns the corresponding shadow address FLOORED to  PAGE_SIZE
// If the shadow page does not exist a new one is MMAPed

inline uint8_t * GetOrCreateShadowBaseAddress(void * address) {
    // No entries at all ?
    uint8_t * shadowPage;
    uint8_t  *** l1Ptr = &gL1PageTable[LEVEL_1_PAGE_TABLE_SLOT(address)];
    if ( *l1Ptr == 0) {
        //lele: L1 entry for that address is empty
        //  - create a new L2 page table, write address to L1 page table entry *l1Ptr
        //  - use mmap to get the shadow memory page for address
        //
        *l1Ptr =  (uint8_t **) calloc(1,LEVEL_2_PAGE_TABLE_SIZE);
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * (1 + sizeof(uint8_t*)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        
    } else if((shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)]) == 0 ){
        // get shadowPage using L2 entry 
        // if the entry is empty, create a new shadow page using mmap
        // otherwise, we have the shadowPage as the address of the shadow page.
        //
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * (1 + sizeof(uint8_t*)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    }
    
    return shadowPage;
}

// Given a address generated by the program, returns the corresponding shadow address FLOORED to  PAGE_SIZE
// If the shadow page does not exist none is created instead 0 is returned

inline uint8_t * GetShadowBaseAddress(void * address) {
    // No entries at all ?
    uint8_t * shadowPage;
    uint8_t *** l1Ptr = &gL1PageTable[LEVEL_1_PAGE_TABLE_SLOT(address)];
    if ( *l1Ptr == 0) {
        return 0;
    } else if((shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)]) == 0 ){
        return 0;
    }
    return shadowPage;
}


#ifndef MULTI_THREADED

//lele: here in IP_AND_CCT mode: use this to count instructions;
// (PANDA use InstructionContributionOfBBL1Byte to count in per whole trace.)
// Increments bytes written in corresponding counters

inline VOID Do1ByteCount() {
	g1ByteWriteInstrCount ++;
}

inline VOID Do2ByteCount() {
	g2ByteWriteInstrCount ++;
}

inline VOID Do4ByteCount() {
	g4ByteWriteInstrCount ++;
}

inline VOID Do8ByteCount() {
    //printf("%s\n",__FUNCTION__);
	g8ByteWriteInstrCount ++;
}

inline VOID Do10ByteCount() {
	g10ByteWriteInstrCount ++;
}

inline VOID Do16ByteCount() {
	g16ByteWriteInstrCount ++;
}

//inline VOID DoLargeByteCount(UINT32 cnt) {
inline VOID DoLargeByteCount(target_ulong cnt) {
#ifdef TESTING_BYTES    
    gLargeByteWriteInstrCount ++;
    gLargeByteWriteByteCount += cnt;    
#else //no  TESTING_BYTES   
	gLargeByteWriteInstrCount += cnt;
	//gTotalInstCount += cnt;
#endif //endof TESTING_BYTES
}

#else // MULTI_THREADED

// Increments bytes written in corresponding counters under the current thread's CCT

inline VOID Do1ByteCount() {
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt1ByteWriteInstrCount ++;
}

inline VOID Do2ByteCount() {
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt2ByteWriteInstrCount ++;
}

inline VOID Do4ByteCount() {
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt4ByteWriteInstrCount ++;
}

inline VOID Do8ByteCount() {
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt8ByteWriteInstrCount ++;
}

inline VOID Do10ByteCount() {
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt10ByteWriteInstrCount ++;
}

inline VOID Do16ByteCount() {
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt16ByteWriteInstrCount ++;
}

inline VOID DoLargeByteCount(target_ulong cnt) {    
#ifdef TESTING_BYTES
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mtLargeByteWriteInstrCount ++;
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mtLargeByteWriteByteCount += cnt;
    
#else // no TESTING_BYTES    
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mtLargeByteWriteInstrCount += cnt;
	//gTotalInstCount += cnt;
#endif //endof TESTING_BYTES
}

#endif // end ifndef MULTI_THREADED



inline bool MergedDeadInfoComparer(const DeadInfoForPresentation & first, const DeadInfoForPresentation  &second) {
    return first.count > second.count ? true : false;
}

inline bool DeadInfoComparer(const DeadInfo &first, const DeadInfo &second) {
    return first.count > second.count ? true : false;
}


// Returns true if the given address belongs to one of the loaded binaries
inline bool IsValidIP(ADDRINT ip){
    return true;
}

// Returns true if the given deadinfo belongs to one of the loaded binaries
inline bool IsValidIP(DeadInfo  di){
   
    return true;
}


// Analysis routines to update the shadow memory for different size READs and WRITEs
VOID Record1ByteMemRead( VOID * addr) {
    uint8_t * status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    if (status) {
        // NOT NEEDED status->lastIP = ip;
        *(status + PAGE_OFFSET((uintptr_t)addr))  = ONE_BYTE_READ_ACTION;
    }
}


#ifdef TESTING_BYTES
inline VOID Record1ByteMemWrite(VOID * addr) {
    
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    if(*(status +  PAGE_OFFSET((uintptr_t)addr)) == ONE_BYTE_WRITE_ACTION){
        gFullyKilling1 ++;		
    }
    *(status +  PAGE_OFFSET((uintptr_t)addr)) = ONE_BYTE_WRITE_ACTION;
}

#else  // no TESTING_BYTES
VOID Record1ByteMemWrite(
#ifdef IP_AND_CCT
                         uint32_t slot,
#endif // end IP_AND_CCT                          
                         VOID * addr) {
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    
    void **lastIP = (void **)(status + PAGE_SIZE +  PAGE_OFFSET((uintptr_t)addr) * sizeof(uint8_t*));
    if (*(status +  PAGE_OFFSET((uintptr_t)addr)) == ONE_BYTE_WRITE_ACTION) {
        
        DECLARE_HASHVAR(myhash);
        REPORT_DEAD(CUR_CTXT, OLD_CTXT,myhash, 1);
        
    } else {
        *(status +  PAGE_OFFSET((uintptr_t)addr)) = ONE_BYTE_WRITE_ACTION;
    }
    *lastIP = CUR_CTXT;
}
#endif // end TESTING_BYTES

inline VOID Record1ByteMemWriteWithoutDead(
#ifdef IP_AND_CCT
                                           uint32_t slot,
#endif
                                           VOID * addr) {
    
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    
    void **lastIP = (void **)(status + PAGE_SIZE +  PAGE_OFFSET((uintptr_t)addr) * sizeof(uint8_t*));
    *(status +  PAGE_OFFSET((uintptr_t)addr)) = ONE_BYTE_WRITE_ACTION;
    *lastIP = CUR_CTXT;
}


VOID Record2ByteMemRead( VOID * addr) {
    uint8_t * status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    if(PAGE_OFFSET((uintptr_t)addr) != PAGE_OFFSET_MASK){
        if(status){
            *((uint16_t *)(status + PAGE_OFFSET((uintptr_t)addr)))  = TWO_BYTE_READ_ACTION;
        }
    } else {
        if(status){
            *(status + PAGE_OFFSET_MASK)  = ONE_BYTE_READ_ACTION;
        }
        status = GetShadowBaseAddress(((char *)addr) + 1);
        if(status){
            *status  = ONE_BYTE_READ_ACTION;
        }
    }
}
#ifdef TESTING_BYTES
VOID Record2ByteMemWrite(VOID * addr) {
 	RecordNByteMemWrite(uint16_t, 2, TWO);
}
#else // no bytes test 
VOID Record2ByteMemWrite(
#ifdef IP_AND_CCT
                         uint32_t slot,
#endif
                         VOID * addr) {
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    // status == 0 if not created.
    if(PAGE_OFFSET((uintptr_t)addr) != PAGE_OFFSET_MASK){
        void **lastIP = (void **)(status + PAGE_SIZE +  PAGE_OFFSET((uintptr_t)addr) * sizeof(uint8_t*));
        uint16_t state = *((uint16_t*)(status +  PAGE_OFFSET((uintptr_t)addr)));
        if ( state != TWO_BYTE_READ_ACTION) { 
            DECLARE_HASHVAR(myhash);
            // fast path where all bytes are dead by same context
            if ( state == TWO_BYTE_WRITE_ACTION && lastIP[0] == lastIP[1]) {
                REPORT_DEAD(CUR_CTXT, (*lastIP), myhash, 2);
                // State is already written, so no need to dead write in a tool that detects dead writes
            } else {
                // slow path 
                // byte 1 dead ?
                REPORT_IF_DEAD(0x00ff, CUR_CTXT, lastIP[0], myhash);
                // byte 2 dead ?
                REPORT_IF_DEAD(0xff00, CUR_CTXT, lastIP[1], myhash);
                // update state for all
                *((uint16_t* )(status +  PAGE_OFFSET((uintptr_t)addr))) = TWO_BYTE_WRITE_ACTION;
            }
        } else {
            // record as written
        	*((uint16_t* )(status +  PAGE_OFFSET((uintptr_t)addr))) = TWO_BYTE_WRITE_ACTION;
        }
        
        lastIP[0] = CUR_CTXT;
        lastIP[1] = CUR_CTXT;        
    } else {
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            addr);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 1);
    }
}
#endif  // end TESTING_BYTES


VOID Record4ByteMemRead( VOID * addr) {
    uint8_t * status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    int overflow = PAGE_OFFSET((uintptr_t)addr) -  (PAGE_OFFSET_MASK - 3);
    if(overflow <= 0 ){
        if(status){
            *((uint32_t *)(status + PAGE_OFFSET((uintptr_t)addr)))  = FOUR_BYTE_READ_ACTION;
        }
    } else {
        if(status){
            status += PAGE_OFFSET((uintptr_t)addr);
            for(int nonOverflowBytes = 0 ; nonOverflowBytes < 4 - overflow; nonOverflowBytes++){
                *(status++)  = ONE_BYTE_READ_ACTION;
            }
        }
        status = GetShadowBaseAddress(((char *)addr) + 4); // +4 so that we get next page
        if(status){
            for( ; overflow; overflow--){
                *(status++)  = ONE_BYTE_READ_ACTION;
            }
        }
    }
}

#ifdef TESTING_BYTES
VOID Record4ByteMemWrite(VOID * addr) {
    RecordNByteMemWrite(uint32_t, 4, FOUR);
}
#else // no TESTING_BYTES

VOID Record4ByteMemWrite(
#ifdef IP_AND_CCT
                         uint32_t slot,
#endif
                         VOID * addr) {
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    // status == 0 if not created.
    if(PAGE_OFFSET((uintptr_t)addr) <  (PAGE_OFFSET_MASK - 2)){
        void **lastIP = (void **)(status + PAGE_SIZE +  PAGE_OFFSET((uintptr_t)addr) * sizeof(uint8_t*));
        uint32_t state = *((uint32_t*)(status +  PAGE_OFFSET((uintptr_t)addr)));   
        
        if (state != FOUR_BYTE_READ_ACTION) {
            
            DECLARE_HASHVAR(myhash);
            void * ipZero = lastIP[0];
            // fast path where all bytes are dead by same context
            if ( state == FOUR_BYTE_WRITE_ACTION &&
                ipZero == lastIP[0] && ipZero == lastIP[1] && ipZero  == lastIP[2] && ipZero  == lastIP[3] ) {
                REPORT_DEAD(CUR_CTXT, ipZero, myhash, 4);
                // State is already written, so no need to dead write in a tool that detects dead writes
            } else {
                // slow path 
                // byte 1 dead ?
                REPORT_IF_DEAD(0x000000ff, CUR_CTXT, ipZero, myhash);
                // byte 2 dead ?
                REPORT_IF_DEAD(0x0000ff00,CUR_CTXT, lastIP[1], myhash);
                // byte 3 dead ?
                REPORT_IF_DEAD(0x00ff0000,CUR_CTXT, lastIP[2], myhash);
                // byte 4 dead ?
                REPORT_IF_DEAD(0xff000000,CUR_CTXT, lastIP[3], myhash);
                // update state for all
                *((uint32_t * )(status +  PAGE_OFFSET((uintptr_t)addr))) = FOUR_BYTE_WRITE_ACTION;
            }
        } else {
            // record as written
        	*((uint32_t * )(status +  PAGE_OFFSET((uintptr_t)addr))) = FOUR_BYTE_WRITE_ACTION;
        }
        
        lastIP[0] = CUR_CTXT;
        // printf("%s, record 4 bytes write to addr %p with context=%p (&gCurrentTraceIpVector[%d])\n",__FUNCTION__,addr, lastIP[0], slot);
        lastIP[1] = CUR_CTXT;
        lastIP[2] = CUR_CTXT;
        lastIP[3] = CUR_CTXT;        
    } else {
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            addr);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 1);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 2);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 3);
    }
}
#endif // end TESTING_BYTES

VOID Record8ByteMemRead( VOID * addr) {
    uint8_t * status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    int overflow = PAGE_OFFSET((uintptr_t)addr) -  (PAGE_OFFSET_MASK - 7);
    if(overflow <= 0 ){
        if(status){
            *((target_ulong *)(status + PAGE_OFFSET((uintptr_t)addr)))  = EIGHT_BYTE_READ_ACTION;
        }
    } else {
        if(status){
            status += PAGE_OFFSET((uintptr_t)addr);
            for(int nonOverflowBytes = 0 ; nonOverflowBytes < 8 - overflow; nonOverflowBytes++){
                *(status++)  = ONE_BYTE_READ_ACTION;
            }
        }
        status = GetShadowBaseAddress(((char *)addr) + 8); // +8 so that we get next page
        if(status){
            for( ; overflow; overflow--){
                *(status++)  = ONE_BYTE_READ_ACTION;
            }
        }       
    }
}

#ifdef TESTING_BYTES
VOID Record8ByteMemWrite(VOID * addr) {
    RecordNByteMemWrite(uint64_t, 8, EIGHT);
}
#else // no TESTING_BYTES

VOID Record8ByteMemWrite(
#ifdef IP_AND_CCT
                         uint32_t slot,
#endif
                         VOID * addr) {
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    // status == 0 if not created.
    if(PAGE_OFFSET((uintptr_t)addr) <  (PAGE_OFFSET_MASK - 6)){
        void **lastIP = (void **)(status + PAGE_SIZE +  PAGE_OFFSET((uintptr_t)addr) * sizeof(uint8_t*));
        uint64_t state = *((uint64_t*)(status +  PAGE_OFFSET((uintptr_t)addr)));   
        
        // printf("%s: current state of addr (%p): 0x%lx\n", 
        //     __FUNCTION__, addr, state);
        // TODO:lele only supports 64bit here.
        if (sizeof(state) == 8 && state != EIGHT_BYTE_READ_ACTION) {
            DECLARE_HASHVAR(myhash);
            void * ipZero = lastIP[0];
            // printf("%s: lastIP[0]=%p\n", __FUNCTION__, ipZero);
            // fast path where all bytes are dead by same context
            // TODO:lele only supports 64bit here.
            if ( sizeof(state) == 8 && state == EIGHT_BYTE_WRITE_ACTION &&
                ipZero  == lastIP[1] && ipZero  == lastIP[2] &&
                ipZero  == lastIP[3] && ipZero  == lastIP[4] &&
                ipZero  == lastIP[5] && ipZero  == lastIP[6] && ipZero  == lastIP[7] ) {
                // printf("%s: dead all 8 on same oldIP\n", __FUNCTION__);
                // REPORT_DEAD(CUR_CTXT, ipZero, myhash, 8);
                // State is already written, so no need to dead write in a tool that detects dead writes
            } else {
                // slow path 
                // byte 1 dead ?
                REPORT_IF_DEAD(0x00000000000000ff, CUR_CTXT, ipZero, myhash);
                // byte 2 dead ?
                REPORT_IF_DEAD(0x000000000000ff00,CUR_CTXT, lastIP[1], myhash);
                // byte 3 dead ?
                REPORT_IF_DEAD(0x0000000000ff0000,CUR_CTXT, lastIP[2], myhash);
                // byte 4 dead ?
                REPORT_IF_DEAD(0x00000000ff000000,CUR_CTXT, lastIP[3], myhash);
                // byte 5 dead ?
                REPORT_IF_DEAD(0x000000ff00000000,CUR_CTXT, lastIP[4], myhash);
                // byte 6 dead ?
                REPORT_IF_DEAD(0x0000ff0000000000,CUR_CTXT, lastIP[5], myhash);
                // byte 7 dead ?
                REPORT_IF_DEAD(0x00ff000000000000,CUR_CTXT, lastIP[6], myhash);
                // byte 8 dead ?
                REPORT_IF_DEAD(0xff00000000000000,CUR_CTXT, lastIP[7], myhash);
                
                // update state for all
                *((uint64_t * )(status +  PAGE_OFFSET((uintptr_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
            }
        } else {
            // record as written
        	*((uint64_t * )(status +  PAGE_OFFSET((uintptr_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
        }
        lastIP[0] = CUR_CTXT;
        // printf("%s, record 8 bytes write to addr %p with context=%p (&gCurrentTraceIpVector[%d])\n",__FUNCTION__,addr, lastIP[0], slot);
        lastIP[1] = CUR_CTXT;
        lastIP[2] = CUR_CTXT;
        lastIP[3] = CUR_CTXT;
        lastIP[4] = CUR_CTXT;
        lastIP[5] = CUR_CTXT;
        lastIP[6] = CUR_CTXT;
        lastIP[7] = CUR_CTXT;        
    } else {
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            addr);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 1);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 2);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 3);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 4);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 5);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 6);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 7);
    }
}
#endif      // end TESTING_BYTES

VOID Record10ByteMemRead( VOID * addr) {
    uint8_t * status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    int overflow = PAGE_OFFSET((uintptr_t)addr) -  (PAGE_OFFSET_MASK - 15);
    if(overflow <= 0 ){
        if(status){
            *((uint64_t *)(status + PAGE_OFFSET((uintptr_t)addr)))  = EIGHT_BYTE_READ_ACTION;
            *((uint16_t *)(status + PAGE_OFFSET(((uintptr_t)addr + 8))))  = TWO_BYTE_READ_ACTION;
        }
    } else {
        // slow path
        Record8ByteMemRead(addr);
        Record2ByteMemRead((char*)addr + 8);
    }
}



#ifdef TESTING_BYTES
VOID Record10ByteMemWrite(VOID * addr) {
    
    
    
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    if(PAGE_OFFSET((uintptr_t)addr) <  (PAGE_OFFSET_MASK - 14)){
        uint64_t state1 = *((uint64_t*)(status +  PAGE_OFFSET((uintptr_t)addr)));
        uint16_t state2 = *((uint64_t*)(status +  PAGE_OFFSET(((uintptr_t)addr) + 8 )));
        if ( (state1 != EIGHT_BYTE_READ_ACTION) || (state2 != TWO_BYTE_READ_ACTION)) {
            if ( (state1 == EIGHT_BYTE_WRITE_ACTION) && (state2 == TWO_BYTE_WRITE_ACTION)) {
                gFullyKilling10 ++;
            } else {
                gPartiallyKilling10 ++;
                for(uint64_t s = state1; s != 0 ; s >>= 8)
                    if(s & 0xff)
                        gPartiallyDeadBytes10++;
                for(uint16_t s = state2; s != 0 ; s >>= 8)
                    if(s & 0xff)
                        gPartiallyDeadBytes10++;
            }
        }
        *((uint64_t* )(status +  PAGE_OFFSET((uintptr_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
        *((uint16_t* )(status +  PAGE_OFFSET(((uintptr_t)addr) + 8))) = TWO_BYTE_WRITE_ACTION;
    } else {
        uint8_t state = *((uint8_t*)(status +  PAGE_OFFSET((uintptr_t)addr)));
        *((uint8_t*)(status +  PAGE_OFFSET((uintptr_t)addr))) = ONE_BYTE_WRITE_ACTION;
        uint8_t deadBytes =  state == ONE_BYTE_WRITE_ACTION ? 1 :0;
        for(uint8_t i = 1 ; i < 10; i++){
            status = GetOrCreateShadowBaseAddress(((char *) addr ) + i);
            state = *((uint8_t*)(status +  PAGE_OFFSET((((uintptr_t)addr) + i))));
            if(state == ONE_BYTE_WRITE_ACTION)
                deadBytes++;
            *((uint8_t*)(status +  PAGE_OFFSET((((uintptr_t)addr) + i)))) = ONE_BYTE_WRITE_ACTION;
        }
        if(deadBytes == 10)
            gFullyKilling10 ++;
        else if(deadBytes){
            gPartiallyKilling10 ++;
            gPartiallyDeadBytes10 += deadBytes;
        }
    }
    
}
#else // no TESTING_BYTES

VOID Record10ByteMemWrite(
#ifdef IP_AND_CCT
                          uint32_t slot,
#endif
                          VOID * addr) {
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    // status == 0 if not created.
    if(PAGE_OFFSET((uintptr_t)addr) <  (PAGE_OFFSET_MASK - 8)){
        void **lastIP = (void **)(status + PAGE_SIZE +  PAGE_OFFSET((uintptr_t)addr) * sizeof(uint8_t*));
        uint64_t state = *((uint64_t*)(status +  PAGE_OFFSET((uintptr_t)addr)));   
        if ( sizeof(state) == 8 && state != EIGHT_BYTE_READ_ACTION) {
            
            DECLARE_HASHVAR(myhash);
            void * ipZero = lastIP[0];
            // fast path where all bytes are dead by same context
            if (  sizeof(state) == 8 && state == EIGHT_BYTE_WRITE_ACTION && 
                ipZero  == lastIP[1] && ipZero  == lastIP[2] && 
                ipZero  == lastIP[3] && ipZero  == lastIP[4] && 
                ipZero  == lastIP[5] && ipZero  == lastIP[6] && ipZero  == lastIP[7] ) {
            	REPORT_DEAD(CUR_CTXT, ipZero, myhash, 8);
                
                // No state update needed
            } else { 
                // slow path 
            	// byte 1 dead ?
            	REPORT_IF_DEAD(0x00000000000000ff, CUR_CTXT, ipZero, myhash);
            	// byte 2 dead ?
            	REPORT_IF_DEAD(0x000000000000ff00,CUR_CTXT, lastIP[1], myhash);                                                            
            	// byte 3 dead ?
            	REPORT_IF_DEAD(0x0000000000ff0000,CUR_CTXT, lastIP[2], myhash);
            	// byte 4 dead ?
            	REPORT_IF_DEAD(0x00000000ff000000,CUR_CTXT, lastIP[3], myhash); 
            	// byte 5 dead ?
            	REPORT_IF_DEAD(0x000000ff00000000,CUR_CTXT, lastIP[4], myhash);                                                            
            	// byte 6 dead ?
            	REPORT_IF_DEAD(0x0000ff0000000000,CUR_CTXT, lastIP[5], myhash);
            	// byte 7 dead ?
            	REPORT_IF_DEAD(0x00ff000000000000,CUR_CTXT, lastIP[6], myhash); 
                // byte 8 dead ?
                REPORT_IF_DEAD(0xff00000000000000,CUR_CTXT, lastIP[7], myhash); 
                
                // update state of these 8 bytes could be some overwrites
                *((uint64_t * )(status +  PAGE_OFFSET((uintptr_t)addr))) = EIGHT_BYTE_WRITE_ACTION;                
            }
        } else {
            // update state of these 8 bytes
            *((uint64_t * )(status +  PAGE_OFFSET((uintptr_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
        }
        
        state = (*((uint16_t*) (status +  PAGE_OFFSET((uintptr_t)addr) + 8)) )| 0xffffffffffff0000;   
        if (sizeof(state)==8 && state != EIGHT_BYTE_READ_ACTION) {
            
            DECLARE_HASHVAR(myhash);
            void * ipZero = lastIP[8];
            // fast path where all bytes are dead by same context
            if ( sizeof(state) == 8 && state == EIGHT_BYTE_WRITE_ACTION && 
                ipZero == lastIP[9]) {
            	REPORT_DEAD(CUR_CTXT, ipZero, myhash, 2);
                // No state update needed
            } else { 
                // slow path 
            	// byte 1 dead ?
            	REPORT_IF_DEAD(0x00ff, CUR_CTXT, ipZero, myhash);
            	// byte 2 dead ?
            	REPORT_IF_DEAD(0xff00,CUR_CTXT, lastIP[9], myhash);                                                            
                // update state
                *((uint16_t * )(status +  PAGE_OFFSET(((uintptr_t)addr + 8)))) = TWO_BYTE_WRITE_ACTION;                
            }
        } else {
            // Update state of these 2 bytes
            *((uint16_t * )(status +  PAGE_OFFSET(((uintptr_t)addr + 8)))) = TWO_BYTE_WRITE_ACTION;
        }
        
        lastIP[0] = CUR_CTXT;
        lastIP[1] = CUR_CTXT;
        lastIP[2] = CUR_CTXT;
        lastIP[3] = CUR_CTXT;
        lastIP[4] = CUR_CTXT;
        lastIP[5] = CUR_CTXT;
        lastIP[6] = CUR_CTXT;
        lastIP[7] = CUR_CTXT;
        lastIP[8] = CUR_CTXT;
        lastIP[9] = CUR_CTXT;
    } else {
        for(int i = 0; i < 10; i++) {
            Record1ByteMemWrite(
#ifdef IP_AND_CCT
                                slot,
#endif
                                ((char *) addr ) + i);
        }
    }
}
#endif // end TESTING_BYTES



VOID Record16ByteMemRead( VOID * addr) {
    uint8_t * status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    int overflow = PAGE_OFFSET((uintptr_t)addr) -  (PAGE_OFFSET_MASK - 15);
    if(overflow <= 0 ){
        if(status){
            *((uint64_t *)(status + PAGE_OFFSET((uintptr_t)addr)))  = EIGHT_BYTE_READ_ACTION;
            *((uint64_t *)(status + PAGE_OFFSET(((uintptr_t)addr + 8))))  = EIGHT_BYTE_READ_ACTION;
        }
    } else {
        // slow path
        Record8ByteMemRead(addr);
        Record8ByteMemRead((char*)addr + 8);
    }
}


#ifdef TESTING_BYTES
VOID Record16ByteMemWrite(VOID * addr) {
    
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    if(PAGE_OFFSET((uintptr_t)addr) <  (PAGE_OFFSET_MASK - 14)){
        uint64_t state1 = *((uint64_t*)(status +  PAGE_OFFSET((uintptr_t)addr)));
        uint64_t state2 = *((uint64_t*)(status +  PAGE_OFFSET(((uintptr_t)addr) + 8 )));
        if ( (state1 != EIGHT_BYTE_READ_ACTION) || (state2 != EIGHT_BYTE_READ_ACTION)) {
            if ( (state1 == EIGHT_BYTE_WRITE_ACTION) && (state2 == EIGHT_BYTE_WRITE_ACTION)) {
                gFullyKilling16 ++;
            } else {
                gPartiallyKilling16 ++;
                for(uint64_t s = state1; s != 0 ; s >>= 8)
                    if(s & 0xff)
                        gPartiallyDeadBytes16++;
                for(uint64_t s = state2; s != 0 ; s >>= 8)
                    if(s & 0xff)
                        gPartiallyDeadBytes16++;
            }
        }
        *((uint64_t* )(status +  PAGE_OFFSET((uintptr_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
        *((uint64_t* )(status +  PAGE_OFFSET(((uintptr_t)addr) + 8))) = EIGHT_BYTE_WRITE_ACTION;
    } else {
        uint8_t state = *((uint8_t*)(status +  PAGE_OFFSET((uintptr_t)addr)));
        *((uint8_t*)(status +  PAGE_OFFSET((uintptr_t)addr))) = ONE_BYTE_WRITE_ACTION;
        uint8_t deadBytes =  state == ONE_BYTE_WRITE_ACTION ? 1 :0;
        for(uint8_t i = 1 ; i < 16; i++){
            status = GetOrCreateShadowBaseAddress(((char *) addr ) + i);
            state = *((uint8_t*)(status +  PAGE_OFFSET((((uintptr_t)addr) + i))));
            if(state == ONE_BYTE_WRITE_ACTION)
                deadBytes++;
            *((uint8_t*)(status +  PAGE_OFFSET((((uintptr_t)addr) + i)))) = ONE_BYTE_WRITE_ACTION;
        }
        if(deadBytes == 16)
            gFullyKilling16 ++;
        else if(deadBytes){
            gPartiallyKilling16 ++;
            gPartiallyDeadBytes16 += deadBytes;
        }
    }
    
}
#else // no TESTING_BYTES

VOID Record16ByteMemWrite(
#ifdef IP_AND_CCT
                          uint32_t slot,
#endif
                          VOID * addr) {
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    // status == 0 if not created.
    if(PAGE_OFFSET((uintptr_t)addr) <  (PAGE_OFFSET_MASK - 14)){
        void **lastIP = (void **)(status + PAGE_SIZE +  PAGE_OFFSET((uintptr_t)addr) * sizeof(uint8_t*));
        uint64_t state = *((uint64_t*)(status +  PAGE_OFFSET((uintptr_t)addr)));   
        if (sizeof(state)==8 && state != EIGHT_BYTE_READ_ACTION) {
            
            DECLARE_HASHVAR(myhash);
            void * ipZero = lastIP[0];
            // fast path where all bytes are dead by same context
            if (sizeof(state)==8 && state == EIGHT_BYTE_WRITE_ACTION && 
                ipZero  == lastIP[1] && ipZero  == lastIP[2] && 
                ipZero  == lastIP[3] && ipZero  == lastIP[4] && 
                ipZero  == lastIP[5] && ipZero  == lastIP[6] && ipZero  == lastIP[7] ) {
            	REPORT_DEAD(CUR_CTXT, ipZero, myhash, 8);
                
                // No state update needed
            } else { 
                // slow path 
            	// byte 1 dead ?
            	REPORT_IF_DEAD(0x00000000000000ff, CUR_CTXT, ipZero, myhash);
            	// byte 2 dead ?
            	REPORT_IF_DEAD(0x000000000000ff00,CUR_CTXT, lastIP[1], myhash);                                                            
            	// byte 3 dead ?
            	REPORT_IF_DEAD(0x0000000000ff0000,CUR_CTXT, lastIP[2], myhash);
            	// byte 4 dead ?
            	REPORT_IF_DEAD(0x00000000ff000000,CUR_CTXT, lastIP[3], myhash); 
            	// byte 5 dead ?
            	REPORT_IF_DEAD(0x000000ff00000000,CUR_CTXT, lastIP[4], myhash);                                                            
            	// byte 6 dead ?
            	REPORT_IF_DEAD(0x0000ff0000000000,CUR_CTXT, lastIP[5], myhash);
            	// byte 7 dead ?
            	REPORT_IF_DEAD(0x00ff000000000000,CUR_CTXT, lastIP[6], myhash); 
                // byte 8 dead ?
                REPORT_IF_DEAD(0xff00000000000000,CUR_CTXT, lastIP[7], myhash); 
                
                // update state of these 8 bytes could be some overwrites
                *((uint64_t * )(status +  PAGE_OFFSET((uintptr_t)addr))) = EIGHT_BYTE_WRITE_ACTION;                
            }
        } else {
            // update state of these 8 bytes
            *((uint64_t * )(status +  PAGE_OFFSET((uintptr_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
        }
        
        state = *((uint64_t*) (status +  PAGE_OFFSET((uintptr_t)addr) + 8));   
        if (sizeof(state)==8 && state != EIGHT_BYTE_READ_ACTION) {
            
            DECLARE_HASHVAR(myhash);
            void * ipZero = lastIP[8];
            // fast path where all bytes are dead by same context
            if ( state == EIGHT_BYTE_WRITE_ACTION && 
                ipZero == lastIP[9] && ipZero  == lastIP[10] && ipZero  == lastIP[11] && 
                ipZero  == lastIP[12] && ipZero  == lastIP[13] && 
                ipZero  == lastIP[14] && ipZero  == lastIP[15]) {
            	REPORT_DEAD(CUR_CTXT, ipZero, myhash, 8);
                // No state update needed
            } else { 
                // slow path 
            	// byte 1 dead ?
            	REPORT_IF_DEAD(0x00000000000000ff, CUR_CTXT, ipZero, myhash);
            	// byte 2 dead ?
            	REPORT_IF_DEAD(0x000000000000ff00,CUR_CTXT, lastIP[9], myhash);                                                            
            	// byte 3 dead ?
            	REPORT_IF_DEAD(0x0000000000ff0000,CUR_CTXT, lastIP[10], myhash);
            	// byte 4 dead ?
            	REPORT_IF_DEAD(0x00000000ff000000,CUR_CTXT, lastIP[11], myhash); 
            	// byte 5 dead ?
            	REPORT_IF_DEAD(0x000000ff00000000,CUR_CTXT, lastIP[12], myhash);                                                            
            	// byte 6 dead ?
            	REPORT_IF_DEAD(0x0000ff0000000000,CUR_CTXT, lastIP[13], myhash);
            	// byte 7 dead ?
            	REPORT_IF_DEAD(0x00ff000000000000,CUR_CTXT, lastIP[14], myhash); 
                // byte 8 dead ?
                REPORT_IF_DEAD(0xff00000000000000,CUR_CTXT, lastIP[15], myhash); 
                // update state
                *((uint64_t * )(status +  PAGE_OFFSET(((uintptr_t)addr + 8)))) = EIGHT_BYTE_WRITE_ACTION;                
            }
        } else {
            // Update state of these 8 bytes
            *((uint64_t * )(status +  PAGE_OFFSET(((uintptr_t)addr + 8)))) = EIGHT_BYTE_WRITE_ACTION;
        }
        
        lastIP[0] = CUR_CTXT;
        lastIP[1] = CUR_CTXT;
        lastIP[2] = CUR_CTXT;
        lastIP[3] = CUR_CTXT;
        lastIP[4] = CUR_CTXT;
        lastIP[5] = CUR_CTXT;
        lastIP[6] = CUR_CTXT;
        lastIP[7] = CUR_CTXT;
        lastIP[8] = CUR_CTXT;
        lastIP[9] = CUR_CTXT;
        lastIP[10] = CUR_CTXT;
        lastIP[11] = CUR_CTXT;
        lastIP[12] = CUR_CTXT;
        lastIP[13] = CUR_CTXT;
        lastIP[14] = CUR_CTXT;
        lastIP[15] = CUR_CTXT;        
    } else {
        for(int i = 0; i < 16; i++) {
            Record1ByteMemWrite(
#ifdef IP_AND_CCT
                                slot,
#endif
                                ((char *) addr ) + i);
        }
    }
}
#endif  // end TESTING_BYTES


//// IMPROVE ME 
VOID RecordLargeMemRead( VOID * addr, UINT32 size) {
    for(UINT32 i = 0 ;i < size; i++){
        uint8_t * status = GetShadowBaseAddress(((char *) addr) + i);
        if(status){
            *(status + PAGE_OFFSET(((uintptr_t)addr + i)))  = ONE_BYTE_READ_ACTION;
        }
    }	
}

#ifdef  TESTING_BYTES

VOID RecordLargeMemWrite(VOID * addr, UINT32 size) {
    uint8_t * status ;
    uint8_t state;
    uint8_t deadBytes =  0;
    for(uint8_t i = 0 ; i < size; i++){
	    status = GetOrCreateShadowBaseAddress(((char *) addr ) + i);
	    state = *((uint8_t*)(status +  PAGE_OFFSET((((uintptr_t)addr) + i))));
	    if(state == ONE_BYTE_WRITE_ACTION)
		    deadBytes++;
	    *((uint8_t*)(status +  PAGE_OFFSET((((uintptr_t)addr) + i)))) = ONE_BYTE_WRITE_ACTION;
    }
    if(deadBytes == size){
	    gFullyKillingLarge ++;
    }
    else if(deadBytes){
	    gPartiallyKillingLarge ++;
    }
    // for large we just add them all to partially dead
    gPartiallyDeadBytesLarge += deadBytes;
    //assert(0 && "NOT IMPLEMENTED LARGE WRITE BYTE");
	
}

#else // no TESTING_BYTES

//// IMPROVE  ME 
VOID RecordLargeMemWrite(
#ifdef IP_AND_CCT
                         uint32_t     slot,
#endif
                         VOID * addr, UINT32 size) {
    for(UINT32 i = 0 ; i < size ; i++) {	
        // report dead for first byte if needed
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            (char *)addr + i);
        
    } 
}
#endif      // end TESTING_BYTES

void InspectMemRead(VOID * addr, UINT32 sz){
    std::cerr<<"\n"<<addr<<":"<<sz;
}


#ifdef MULTI_THREADED
// MT support
volatile bool gDSLock;
inline VOID TakeLock(){
    do{
        while(gDSLock);   
    }while(!__sync_bool_compare_and_swap(&gDSLock,0,1));
}

inline VOID ReleaseLock(){
    gDSLock = 0;
}
#endif // end MULTI_THREADED

// //void pfun(VarType var_ty, const char *var_nm, LocType loc_t, target_ulong loc, void *in_args){
// void pfun(void *var_ty_void, const char *var_nm, LocType loc_t, target_ulong loc, void *in_args){
//     const char *var_ty = dwarf_type_to_string((DwarfVarType *) var_ty_void);
//     //const char *var_ty = "";
//     // restore args
//     struct args *args = (struct args *) in_args;
//     CPUState *pfun_cpu = args->cpu;
//     CPUArchState *pfun_env = (CPUArchState*)pfun_cpu->env_ptr;
//     //const char *src_filename = args->src_filename;
//     //uint64_t src_linenum = args->src_linenum;

//     target_ulong guest_dword;
//     switch (loc_t){
//         case LocReg:
//             printf("VAR REG: %s %s in Reg %d", var_ty, var_nm, loc);
//             printf("    => 0x%x\n", pfun_env->regs[loc]);
//             break;
//         case LocMem:
//             printf("VAR MEM: %s %s @ 0x%x", var_ty, var_nm, loc);
//             panda_virtual_memory_rw(pfun_cpu, loc, (uint8_t *)&guest_dword, sizeof(guest_dword), 0);
//             printf("    => 0x%x\n", guest_dword);
//             break;
//         case LocConst:
//             printf("VAR CONST: %s %s as 0x%x\n", var_ty, var_nm, loc);
//             break;
//         case LocErr:
//             printf("VAR does not have a location we could determine. Most likely because the var is split among multiple locations\n");
//             break;
//     }
// }

// void on_line_change(CPUState *cpu, target_ulong pc, const char *file_Name, const char *funct_name, unsigned long long lno){
//     struct args args = {cpu, file_Name, lno};
//     printf("[%s] %s(), ln: %4lld, pc @ 0x%x\n",file_Name, funct_name,lno,pc);
//     pri_funct_livevar_iter(cpu, pc, (liveVarCB) pfun, (void *) &args);
// }

/*
    void getAndSetSrcInfo:

    called during mem_callback, given pc, find source code info: line number and source file name, or even debug symbols (such as variable name and value) if wanted
        - line/file info are stored in gAsidPCtoFileLine
        - will check if pc exists before add.
// */
// void getAndSetSrcInfo(CPUState *cpu, target_ulong pc, target_ulong addr, bool isWrite, target_ulong target_asid){
//     SrcInfo info;
//     // if NOT in source code, just return
//     printf("Now in %s, now call: %p\n", __FUNCTION__, &pri_get_pc_source_info);
//     // printf("Now in %s &info: %p\n", __FUNCTION__, &info);
    
    
//     int rc = pri_get_pc_source_info(cpu, pc, &info);
//     // printf("%s: done call: %p\n", __FUNCTION__, &pri_get_pc_source_info);

//     // We are not in dwarf info
//     if (rc == -1){
//         // printf("%s: we are not in dwarf info\n", __FUNCTION__);
//         return;
//     }
//     // We are in the first byte of a .plt function
//     if (rc == 1) {
//         // printf("%s: we are in the first byte of a .plt function\n", __FUNCTION__);
//         return;
//     }

//     // printf("%s: file: %s, line: %lu==, asid: 0x" TARGET_FMT_lx "\n", 
//     //     __FUNCTION__, info.filename, info.line_number, target_asid);

//     // exit(-1);

//     std::tr1::unordered_map<ADDRINT, std::tr1::unordered_map<ADDRINT, FileLineInfo *> *>::iterator asidMapIt = gAsidPCtoFileLine.find(target_asid);

//     std::tr1::unordered_map<ADDRINT, FileLineInfo *> *asidMap;

//     if (asidMapIt == gAsidPCtoFileLine.end()){
//         // no map for this asid yet, create one
//         asidMap = new std::tr1::unordered_map<ADDRINT, FileLineInfo *>;
//         gAsidPCtoFileLine[gTargetAsid] = asidMap;
//     }else{
//         asidMap = gAsidPCtoFileLine[gTargetAsid];
//     }

//     std::tr1::unordered_map<ADDRINT, FileLineInfo *>::iterator lineForPcIt = (*asidMap).find(pc);
//     FileLineInfo *lineForPc;
//     if (lineForPcIt == (*asidMap).end()){
//         // no line info for pc, create one
//         lineForPc= new FileLineInfo;
//         std::string fileN(info.filename);
//         std::string funN(info.funct_name);
//         lineForPc->valid = true;
//         lineForPc->fileName = fileN;
//         lineForPc->funName = funN;
//         lineForPc->lineNum = info.line_number;
//         (*asidMap)[pc] = lineForPc;
//     }else{
//         // line info exists, check whether changes
//         lineForPc = (*asidMap)[pc];
//         FileLineInfo newLineInfo;
//         newLineInfo.valid = true;
//         newLineInfo.lineNum=info.line_number;
//         newLineInfo.fileName=std::string(info.filename);
//         newLineInfo.funName=std::string(info.funct_name);

//         if(! (newLineInfo == *lineForPc)){
//             printf("%s: ERROR: file/line info inconsistent for pc: 0x" TARGET_FMT_lx "\n", __FUNCTION__, pc);
//             printf("%s: \t old file name: %s, new file name: %s\n", __FUNCTION__, lineForPc->fileName.c_str(), newLineInfo.fileName.c_str());
//             printf("%s: \t old func name: %s, new func name: %s\n", __FUNCTION__, lineForPc->funName.c_str(), newLineInfo.funName.c_str());
//             printf("%s: \t old line: %lu, new line: %lu\n", __FUNCTION__, lineForPc->lineNum, newLineInfo.lineNum);
//             exit(-1);
//         }
       
//     }

//     // struct args args = {cpu, NULL, 0};
//     // pri_funct_livevar_iter(cpu, pc, (liveVarCB) pfun, (void *) &args);
//     // char *symbol_name = pri_get_vma_symbol(cpu, pc, addr);
//     // if (!symbol_name){
//     //     // symbol was not found for particular addr
//     //     if (isWrite) {
//     //         printf ("Virt mem write at 0x%x - (NONE)\n", addr);
//     //     }
//     //     else {
//     //         printf ("Virt mem read at 0x%x - (NONE)\n", addr);
//     //     }
//     //     return 0;
//     // }
//     // else {
//     //     if (isWrite) {
//     //         printf ("Virt mem write at 0x%x - \"%s\"\n", addr, symbol_name);
//     //     }
//     //     else {
//     //         printf ("Virt mem read at 0x%x - \"%s\"\n", addr, symbol_name);
//     //     }
//     // }
//     // return 0;
// }


// this creates BOTH the global for this callback fn (on_ssm_func)
// and the function used by other plugins to register a fn (add_on_ssm)
//PPP_CB_BOILERPLATE(on_trace_mem_asid)

// this creates the 

int mem_callback(CPUState *cpu, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf, bool is_write){
    //prog_point p = {};
    //get_prog_point(cpu, &p);


    // target_ulong asid_cur = panda_current_asid_proc_struct(cpu);

// #if defined(TARGET_I386) && !defined(TARGET_X86_64)
    // getAndSetSrcInfo(cpu, pc, addr, is_write, asid_cur);
// #endif

    // target_ulong asid_cur = 0;

    // if (p.cr3 != asid_cur){
    //     //printf("ERROR: panda_current_asid_proc_struct is not equal with p.cr3 (p.cr3: %p, cur_asid: %p)\n", (void *)(uintptr_t)p.cr3, (void *)(uintptr_t)asid_cur );
    //     //exit(-1);
    // }else{
    //      //printf("panda_current_asid_proc_struct is equal with p.cr3 (p.cr3: %p, cur_asid: %p)\n", (void *)(uintptr_t)p.cr3, (void *)(uintptr_t)asid_cur );
    // }
    
    //lele: filter out the processes(threads?) according to its ASID    
    //printf("curASID: " TARGET_FMT_lx "\n", callstack.asid);
    // if (gTraceOne){
    //     if (asid_cur != gTargetAsid){
    //         //printf("%s: ignore ASID 0x" TARGET_FMT_lx "\n", __FUNCTION__, asid_cur);
    //         gIgnoredASIDs.insert(asid_cur);
    //         return 1;
    //     } 
    //     // else{
    //     //     printf("%s: trace one ASID: 0x" TARGET_FMT_lx "\n", __FUNCTION__, gTargetAsid);
    //     // }
    // }else if (gTraceKernel){
    //     if (asid_cur != 0x0 ){
    //         //printf("ignore ASID " TARGET_FMT_lx , p.cr3);
    //         gIgnoredASIDs.insert(asid_cur);
    //         return 1;
    //     } else{
    //         printf("\n Kernel mem op\n");
    //     }
    // }else if (gTraceApp){
    //     if (asid_cur == 0x0 ){
    //         //printf("ignore ASID " TARGET_FMT_lx , p.cr3);
    //         gIgnoredASIDs.insert(asid_cur);
    //         return 1;
    //     } else{
    //         printf("\n App mem op, ASID: 0x" TARGET_FMT_lx "\n", asid_cur);
    //     }
    // }else{
    //     // no filters
    //     printf("\n All: Mem op for ASID: 0x" TARGET_FMT_lx "\n", asid_cur);
    // }
    // printf("Now in %s\n", __FUNCTION__);
    bool judge_by_struct;
    target_ulong judge_asid;
    OsiProc *judge_proc;
    bool is_target = is_target_process_running(cpu, &judge_by_struct, &judge_asid, &judge_proc);

    // print judge metric, for debug
    if(judge_by_struct){
        // printf("--%s: judge by name in struct. \n\ttarget name: %s\n",
        //     __FUNCTION__, gProcToMonitor.c_str());
        printf("--%s: judge by name in struct. \n",
            __FUNCTION__);
        printf("\tasid: (cpu->cr3): " TARGET_FMT_lx "\n", judge_asid);
        //print full info of proc
        print_proc_info(judge_proc);
    }
    else{
        printf("--%s: judge by asid: 0x" TARGET_FMT_lx ", target: 0x" TARGET_FMT_lx "\n",
            __FUNCTION__, judge_asid, gTargetAsid);
    }

    if(!is_target){
        // not target process.

        if(gIsTargetBlock){
            printf("--%s: WARNING: target detected at before_block_exec but not detected here, might a process switch??\n", __FUNCTION__);

            // // print judge metric, for debug
            // if(judge_by_struct){

            //     printf("%s: judge by name in struct. \n",
            //         __FUNCTION__);
            //     printf("\tasid: (cpu->cr3): " TARGET_FMT_lx "\n", judge_asid);
            //     //print full info of proc
            //     print_proc_info(judge_proc);
            // }
            // else{
            //     printf("\t\tjudge by asid: 0x" TARGET_FMT_lx ", target: 0x" TARGET_FMT_lx "\n",
            //         judge_asid, gTargetAsid);
            // }

            // exit(-1);
        }else{
            return 1;
        }
        // return 1;
    }else{
        // is target process
        if (! gIsTargetBlock){
            printf("%s: WARNING: target not detected at before_block_exec, but detected here, might a process switch, or cr3 overlap??\n", __FUNCTION__);

            if (!judge_by_struct) return 1;

            printf("\tWARNING: judge by proc struct!\n");    
            printf("\t------- not cr3 overlap, must be a process switch??\n");

            exit(-1);
        }

        // // print judge metric, for debug
        // if(judge_by_struct){

        //     printf("%s: judge by name in struct. \n",
        //         __FUNCTION__);
        // printf("\tasid: (cpu->cr3): " TARGET_FMT_lx "\n", judge_asid);
        //     //print full info of proc
        //     print_proc_info(judge_proc);
        // }
        // else{
        //     printf("\t\tjudge by asid: 0x" TARGET_FMT_lx ", target: 0x" TARGET_FMT_lx "\n",
        //         judge_asid, gTargetAsid);
        // }
    }


    // reset the flag. will be detect and set again in before_block_exe
    // if(!gIsTargetBlock){
    //     return 1;
    // }

    //##################################################################################
    // lele: ported from Instruction() from Deadspy
    // Basic: find deadwrite to the position
    // - first: get last access, R W
    // - second: if w-w, report it.

    // details steps:
    // 1, count write ops according to write size;
    // 2, update gBlockShadowMap and 

    //###############################################################################
    
    uint32_t slot = 0; // only used for write op.

    // uint32_t slot=gCurrentTraceBlock->nSlots;

    // If it is a memory write then count the number of bytes written 
//#ifndef IP_AND_CCT  
    // //xxx-> IP_AND_CCT uses traces to detect instructions & their write size hence no instruction level counting is needed
    // CHANGE: lele: in PANDA, no trace, so we also use this to count instructions and size. 
    // if(INS_IsMemoryWrite(ins)){
    if(is_write){
        // USIZE writeSize = INS_MemoryWriteSize(ins);
        target_ulong writeSize = size;
        //printf("counting written bytes:  " TARGET_FMT_lu "\n", writeSize);
        switch(writeSize){
            case 1:
                // INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Do1ByteCount, IARG_END);
                Do1ByteCount();
                break;
            case 2:
                Do2ByteCount();
                break;
            case 4:
                Do4ByteCount();
                break;
            case 8:
                Do8ByteCount();
                break;
            case 10:
                Do10ByteCount();
                break;
            case 16:
                Do16ByteCount();
                break;
            default:
                DoLargeByteCount(writeSize);
        }                
    }
//#endif //end  ifndef IP_AND_CCT         
    
    
    // In Multi-threaded skip call, ret and JMP instructions
#ifdef MULTI_THREADED
    if(INS_IsBranchOrCall(ins) || INS_IsRet(ins)){
        return;
    }
#endif //end MULTI_THREADED
    
#ifdef MULTI_THREADED        
    // Support for MT
    // Acquire the lock before starting the analysis routine since we need analysis routine and original instruction to run atomically.
    bool lockNeeded = false;
    if (memOperands) {
        for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) TakeLock, IARG_END);
            lockNeeded = true;
            break;
        }
    }
#endif //end MULTI_THREADED        
    

    // DeadSpy: Iterate over each memory operand of the instruction and add Analysis routine to check for dead writes.
    // We correctly handle instructions that do both read and write.
    // lele: no need to ana operands since it's already mem R/W.
    //
    //  - pc as ins address, addr as mem address, buf[0-size-1] as memory content.
    //
    //  - detect deadwrite.

    // for (UINT32 memOp = 0; memOp < memOperands; memOp++) {

        // UINT32 refSize = INS_MemoryOperandSize(ins, memOp);

    target_ulong refSize = size;
    // if (! is_write){
    //     printf("%s: record read pc: %p, addr: %p (%d bytes).\n",
    //         __FUNCTION__, (void*)(uintptr_t)pc , (void *)(uintptr_t)addr, (int)size);
    // }else{
    if (is_write){
        bool needUpdateTraceBlock=false;

        // printf("%s: record write pc: %p, addr: %p (%d bytes).\n",
        //     __FUNCTION__, (void*)(uintptr_t)pc, (void *)(uintptr_t)addr, (int)size);

        //update ipShadow slot when write detected
        // For each Basic block, in general case, only update once.
        //  - use flag gBlockShadowMapDone[tb->pc] to mark it done at after_block_exe
        // In some corner case, also should update gBlockShadowMap for some old Blocks:
        //  - a new write pc for the old block.
        //  - block size change to be larger then the old size.
        
        // first, get the shadowMap and its current total slots counts;
        // printf("%s: get currentTraceShadowMap for current tb: 0x" TARGET_FMT_lx "\n", 
        //     __FUNCTION__, gCurrentTraceBlock->address);

        auto shadowIt = gBlockShadowMap.find(gCurrentTraceBlock->address) ;
        if (shadowIt == gBlockShadowMap.end()){
            printf("%s: ERROR: no shadowMap created for tb->pc: " TARGET_FMT_lx "\n",
                __FUNCTION__, gCurrentTraceBlock->address);
            exit(-1);
        }

        target_ulong * currentBlockShadowMap = (target_ulong *) gBlockShadowMap[gCurrentTraceBlock->address];
        // printf("%s: get TraceShadowIP array from gBlockShadowMap[gCurrentTraceBlock->address] %p\n", 
        //     __FUNCTION__,currentBlockShadowMap);

        target_ulong recordedSlots = currentBlockShadowMap[-1]; // present one behind
        int blockSize = (int) currentBlockShadowMap[-2];
        // printf("%s: get recordedSlots %d, blockSize: %d\n", __FUNCTION__,(int)recordedSlots, blockSize);

        // second, update slot pc in gBlockShadowMap.
        //  - if pc not in slot, add it to gBlockShadowMap.
        //  - don't use gBlockShadowMapDone anymore. BUG Panda: after execution of a block, _after_block_exec will not run in some cases. This will cause gBlockShadowMapDone not be set to true even if block exe finishes.
        //  - now we don't use gBlockShadowMapDone, so we must check gBlockShadowMap on every mem_callback, this cause more overhead, but safer.
        
        // auto blockDone = gBlockShadowMapDone.find(gCurrentTraceBlock->address);
        // if (blockDone != gBlockShadowMapDone.end()){
        //     printf("%s: No shadowMapDone for tb->pc: 0x" TARGET_FMT_lx " \n",
        //         __FUNCTION__, gCurrentTraceBlock->address);
        // } 
        // if(blockDone->second ){
                //gBlockShadowMapDone[gCurrentTraceBlock->address] == true;

        // 2.1: check whether pc in gBlockShadowMap, by checking gBlockShadowIPtoSlot.
        //      - gBlockShadowIPtoSlot[tb->pc][IP] >=0  if pc in gBlockShadowMap

            //printf("%s: check to update TraceShadowMap if no current pc is stored \n", __FUNCTION__);
            std::tr1::unordered_map <ADDRINT, int> :: iterator mapIptoSlots = (*gBlockShadowIPtoSlot[gCurrentTraceBlock->address]).find(pc);

        // 2.2: update pc and slot index when no pc stored;

            if (mapIptoSlots == (*gBlockShadowIPtoSlot[gCurrentTraceBlock->address]).end() || mapIptoSlots->second == -1){ //TODO: no need to check -1.
                
                // pc not in gBlockShadowMap

                printf("%s: WARNING::::::::::::::::::::::::::::::::::::\n in an old block, but gBlockShadowMap[0x" TARGET_FMT_lx "] has no pc: 0x" TARGET_FMT_lx ", need add it.\n",
                    __FUNCTION__, gCurrentTraceBlock->address, pc);

                //Now update the gBlockShadowMap
                //check if we have enough space left
                if ((int)recordedSlots >= blockSize){
                    printf("%s: ERROR: number of write pcs is larger then block size, this shouldn't happen \n", __FUNCTION__);
                    printf("%s: the size of ShadowMap and block Size is checked before_block_exe. If this still happen, this instruction might have bypassed the callback of before_block_exe.\n", __FUNCTION__);
                    exit(-1);
                    //might replace gBlockShadowMap for this block?
                }
                //Update with a new slot
		        slot = recordedSlots;

                gCurrentSlot = slot + 1;

                currentBlockShadowMap[slot] = pc;
                (*gBlockShadowIPtoSlot[gCurrentTraceBlock->address])[pc] = slot;
                currentBlockShadowMap[-1] ++;
            	// printf("%s: a new pc slot added for block->pc: 0x" TARGET_FMT_lx "\n", __FUNCTION__, gCurrentTraceBlock->address);

                // once we have new slot in gBlockShadowMap for an old block, we also need to update gTraceNode, so that we store a new write pc in slot in childIPs.
                needUpdateTraceBlock=true;

        // 2.3: if pc is found, then set slot value as the stored value.
            }else {
                //mapIptoSlots != (*gBlockShadowIPtoSlot[gCurrentTraceBlock->address]).end())
                // i.e. mapIptoSlots has current write PC/IP stored in block->pc
                // Then, slot will be read from mapIptoSlots<pc, int slot>

                slot = mapIptoSlots->second;
                gCurrentSlot = slot + 1;

                // printf("%s: gBlockShadowMap already has this pc: 0x" TARGET_FMT_lx ", at slot: %d, no need to update\n",__FUNCTION__, pc, (int)slot);
                // needUpdate=false;
            }
        // } else{
            //gBlockShadowMapDone[gCurrentTraceBlock->address] == false;

            // // normal operation, when for the first time the gTraceShadowMap is updated.
            // slot = gCurrentSlot; // only used for write op.
            // gCurrentSlot++; // increase gCurrentSlot index for next use.
            // currentBlockShadowMap[slot] = pc;
            // (*gBlockShadowIPtoSlot[gCurrentTraceBlock->address])[pc]= slot;
            // currentBlockShadowMap[-1] ++;
            // printf("%s: a new pc slot [%d]:IP=0x" TARGET_FMT_lx "  added for a new block->pc: 0x" TARGET_FMT_lx "\n", __FUNCTION__, (int)slot, pc, gCurrentTraceBlock->address);

            // if (!gNewBlockNode){
            //     // check this to make sure we'll also update gCurrentTraceBlock->childIPs
            //     printf("%s: ERROR: should be a new TraceBlockNode, since this is a new block in gTraceShadowMap\n", __FUNCTION__);
            //     exit(-1);
            // }
        // }

//

//
//     if(needUpdate){
//           // currentBlockShadowMap[slot] = pc;
//            currentBlockShadowMap[recordedSlots] = pc;
//            (*gTraceShadowMapIps[gCurrentTraceBlock->address])[pc]=true;
//            currentBlockShadowMap[-1] ++;
//        }


        //Third,  if a new BlockNode, 
        //  - update gCurrentTraceBlock->childIPs;
        //  - also update gCurrentTraceIpVector;
        // if not a new BlockNode, but need update due to a new write pc in a old BlockNode.

        if (gNewBlockNode || needUpdateTraceBlock || gCurrentTraceBlock->childIPs == 0){
            // UpdateTraceIPs is splited into two steps:
            //  1, at at the instrumentBeforeBlockExe: 
            //      initialize as 0 in coutinuous mode.
            //      or allocate all IPs as tb->size (Non-continuous)
            //  2, fill it during mem_callback(here), at the same time when we fill gBlockShadowMap.
            //  --> The goal is that, we could use the &gCurrentTraceIpVector[slot] (or &(gCurrentTraceBlock->childIPs[slot])) to report as dead context.
            //  This way, the gCurrentTraceBlock->childIPs will be filled in the same pace with gBlockShadowMap.
            //
            // Update gTrace->childIPs and -> nSlots by this new slot
            // BTW: The size should be checked at instrumentbeforeBlockExe, or above during update gBlockShadowMap
           
            // helping prints:
            //
            // if (gCurrentTraceBlock->nSlots == 0){
            //     // for first slot, also set childIPs. 
            //     if (gNewBlockNode){
            //         printf("%s: now in first R/W of a new trace\n", __FUNCTION__);
            //     }else{
            //         printf("%s: WARNING: first R/W of an old trace\n", __FUNCTION__);
            //     }

            // }else{

            //     printf("%s: not the first R/W of a new trace\n", __FUNCTION__);

            //     // if not first slot, call this to update IP index.
            //     // 
            //     // printf("%s: not the first R/W of a new trace, just allocate one slot in IpVectBuffer\n", __FUNCTION__);
            //     // GetNextIPVecBuffer(1);
            // }

            //in every mem_callback, Update the TraceBlock's slot index with current Slot, this should be independent with the slot number in gTraceShadowMap.
            // gCurrentTraceBlock->childIPs[slot] = gCurrentTraceBlock;
            gCurrentTraceBlock->nSlots++; 
            // printf("%s: add one Slot in gCurrentTraceBlock &gCurrentTraceBlock->childIPs[%d]: %p; total Slots in trace: %d, block size: %d\n", 
            //     __FUNCTION__, (int)slot, &gCurrentTraceBlock->childIPs[slot], (int)gCurrentTraceBlock->nSlots, blockSize);
            if(gCurrentTraceBlock->nSlots > blockSize){
                printf("%s: ERROR: nSlots in gCurrentTraceBlock is larger than blockSize \n", __FUNCTION__);
                printf("%s: This will probably overlap the following block's buffer in IpVecBuffer\n", __FUNCTION__);
                exit(-1);
            }


            // printf("%s: checking gCurrentTraceIpVector[slot]\n",__FUNCTION__);
            if (gCurrentTraceIpVector[slot] != gCurrentTraceBlock){
                printf("%s: ERROR: gCurrentTraceIpVector[slot] != gCurrentTraceBlock",
                    __FUNCTION__);
            }

        }

        // check IpVector Slot
        if(gCurrentTraceIpVector != gCurrentTraceBlock->childIPs){
            printf("%s: gCorrentIpVector(%p) should always equal to gCurrentTraceBlock->childIPs(%p)\n", __FUNCTION__, gCurrentTraceIpVector, gCurrentTraceBlock->childIPs);
            exit(-1);
        }
        if(!gCurrentTraceIpVector){
            printf("%s: ERROR: gCurrentTraceIpVector is nil\n", __FUNCTION__);
            exit(-1);
        }else if(!gCurrentTraceIpVector[slot]){
            printf("%s: ERROR: IpVector %p[%d] is nil\n", __FUNCTION__,gCurrentTraceIpVector, (int)slot);
            exit(-1);
        }
        // else{
        //     printf("%s: IpVector[%d] is good\n", __FUNCTION__, (int)slot);
        // }

        // gCurrentSlot++;
        // gCurrentTraceBlock->nSlots++;
        // printf("new slot created for gCurrentContext->address: " TARGET_FMT_lx ", %u (%u)\n", gCurrentContext->address, gCurrentSlot,gCurrentTraceBlock->nSlots);



        //target_ulong * currentBlockShadowMap = (target_ulong *) gBlockShadowMap[gCurrentContext->address];
        //printf("set recordedSlots of currentBlockShadowMap[-1] %p to %u\n", currentBlockShadowMap, gCurrentSlot);
        //target_ulong recordedSlots = currentBlockShadowMap[-1]; // 
        //currentBlockShadowMap[-1] = gCurrentSlot; // 

    }
    
    switch(refSize){
        case 1:{
            // if (INS_MemoryOperandIsRead(ins, memOp)) {
                
            if (! is_write) {
                Record1ByteMemRead((VOID *)(uintptr_t)addr);                        
            }
            else {
                Record1ByteMemWrite(
#ifdef IP_AND_CCT
                    slot,
#endif
                    (VOID *)(uintptr_t)addr);                    
//                     INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
//                                                 (AFUNPTR) Record1ByteMemWrite,
// #ifdef IP_AND_CCT
//                                                 IARG_UINT32, slot,
// #endif
//                                                 IARG_MEMORYOP_EA,
//                                                 memOp, IARG_END);
                
            }
        }
            break;
            
        case 2:{
                    
            if (! is_write) {
                Record2ByteMemRead((VOID *)(uintptr_t)addr);                        
            }
            else {
                Record2ByteMemWrite(
#ifdef IP_AND_CCT
                    slot,
#endif
                    (VOID *)(uintptr_t)addr);                }
        }
                
//                 if (INS_MemoryOperandIsRead(ins, memOp)) {
                
//                     INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record2ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
                
//                 }
//                 if (INS_MemoryOperandIsWritten(ins, memOp)) {   
                
//                     INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
//                                                 (AFUNPTR) Record2ByteMemWrite, 
// #ifdef IP_AND_CCT
//                                                 IARG_UINT32, slot,
// #endif
//                                                 IARG_MEMORYOP_EA,
//                                                 memOp, IARG_END);
                
//                 }
        // }
            break;
            
        case 4:{
                    
            if (! is_write) {
                Record4ByteMemRead((VOID *)(uintptr_t)addr);                        
            }
            else {
                Record4ByteMemWrite(
#ifdef IP_AND_CCT
                    slot,
#endif
                    (VOID *)(uintptr_t)addr);                }
        }
            break;
            
        case 8:{
                    
            if (! is_write) {
                Record8ByteMemRead((VOID *)(uintptr_t)addr);                        
            }
            else {
                Record8ByteMemWrite(
#ifdef IP_AND_CCT
                    slot,
#endif
                    (VOID *)(uintptr_t)addr);                }
        }
            break;
            
        case 10:{
            if (! is_write) {
                Record10ByteMemRead((VOID *)(uintptr_t)addr);                        
            }
            else {
                Record10ByteMemWrite(
#ifdef IP_AND_CCT
                    slot,
#endif
                    (VOID *)(uintptr_t)addr);                }
            
        }
            break;
            
        case 16:{ // SORRY! XMM regs use 16 bits :((
//                 if (INS_MemoryOperandIsRead(ins, memOp)) {
                
//                     INS_InsertPredicatedCall(ins, IPOINT_BEFORE,(AFUNPTR) Record16ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
                
//                 }
//                 if (INS_MemoryOperandIsWritten(ins, memOp)) {
                
//                     INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
//                                                 (AFUNPTR) Record16ByteMemWrite,
// #ifdef IP_AND_CCT
//                                                 IARG_UINT32, slot,
// #endif
//                                                 IARG_MEMORYOP_EA,memOp, IARG_END);
                
//                 }

            if (! is_write) {
                Record16ByteMemRead((VOID *)(uintptr_t)addr);                        
            }
            else {
                Record16ByteMemWrite(
#ifdef IP_AND_CCT
                    slot,
#endif
                    (VOID *)(uintptr_t)addr);                }
        }
            break;
            
        default: {
            // seeing some stupid 10, 16, 512 (fxsave)byte operations. Suspecting REP-instructions.
//                 if (INS_MemoryOperandIsRead(ins, memOp)) {
                
//                     INS_InsertPredicatedCall(ins, IPOINT_BEFORE,(AFUNPTR) RecordLargeMemRead, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_END);
                
//                 }
//                 if (INS_MemoryOperandIsWritten(ins, memOp)) {
                
//                     INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
//                                                 (AFUNPTR) RecordLargeMemWrite,
// #ifdef IP_AND_CCT
//                                                 IARG_UINT32, slot,
// #endif
//                                                 IARG_MEMORYOP_EA,memOp, IARG_MEMORYWRITE_SIZE, IARG_END);
                
//                 }

            if (! is_write) {
                RecordLargeMemRead((VOID *)(uintptr_t)addr,size);                        
            }
            else {
                RecordLargeMemWrite(
#ifdef IP_AND_CCT
                    slot,
#endif
                    (VOID *)(uintptr_t)addr, size);
            }
        }
            break;
            //assert( 0 && "BAD refSize");
            
    }
// }

#ifdef MULTI_THREADED
    // Support for MT
    // release the lock if we had taken it
    if (lockNeeded) {            
        INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) ReleaseLock, IARG_END);
    }
#endif //end MULTI_THREADED
        
    return 1;
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
     //return mem_callback(env, pc, addr, size, buf, false, read_text_tracker);
    return mem_callback(env, pc, addr, size, buf, false);

}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    //return mem_callback(env, pc, addr, size, buf, true, write_text_tracker);
    return mem_callback(env, pc, addr, size, buf, true);
}


//#########################################################################
//last STEP: printing
//#########################################################################


int addr2line(std::string debugfile, target_ulong addr, FileLineInfo * lineInfo){
    
    // convert line number to string
    std::stringstream stream;
    stream << std::hex << addr;
    std::string str_addr( stream.str());

    std::string cmd;
    cmd = "addr2line -f -p -e " + debugfile + " 0x" + str_addr;
    std::cout << cmd << std::endl;

    std::string rawLineInfo = runcmd(cmd);

    printf("%s: cmd returned: '%s'\n", __FUNCTION__, rawLineInfo.c_str());

    if (rawLineInfo.find("?? ??:0") != std::string::npos){
        // printf("No result from addr2line\n");
        return -1;

    }else if (rawLineInfo.find("??:?") != std::string::npos){
        // printf("have func but no file/line result from addr2line\n");

        printf("get addr2line result:\n\t%s\n\tnow parse it\n", rawLineInfo.c_str());
        //parse and store it as FileLineInfo struct.
        size_t pos = rawLineInfo.find(" ");
        lineInfo->funName = rawLineInfo.substr(0,pos); //store fun name.

        std::string tmp = rawLineInfo.substr(pos+1); // ignore fun name
        std::cout<<"rest raw after ignore func: "<<tmp<<std::endl;
        
        //find second space, must be after 'at'
        pos = tmp.find(" ");
        tmp = tmp.substr(pos+1); //ignore 'at'
        std::cout<<"rest raw after ignore 'at': "<<tmp<<std::endl;

        lineInfo->lineNum = 0;
        lineInfo->fileName = "file_not_found";
        lineInfo->valid = true;
        lineInfo->extraInfo = tmp;

    }else if (rawLineInfo.find_first_not_of("\n\t ") != std::string::npos){

        printf("get addr2line result:\n\t%s\n\tnow parse it\n", rawLineInfo.c_str());
        //parse and store it as FileLineInfo struct.
        size_t pos = rawLineInfo.find(" ");
        lineInfo->funName = rawLineInfo.substr(0,pos); //store fun name.

        std::string tmp = rawLineInfo.substr(pos+1); // ignore fun name
        std::cout<<"rest raw after ignore func: "<<tmp<<std::endl;
        
        //find second space, must be after 'at'
        pos = tmp.find(" ");
        tmp = tmp.substr(pos+1); //ignore 'at'
        std::cout<<"rest raw after ignore 'at': "<<tmp<<std::endl;

        pos = tmp.find(":");
        lineInfo->fileName = tmp.substr(0, pos);
        tmp = tmp.substr(pos+1); //ignore file name.
        std::cout<<"rest raw after ignore 'filename': "<<tmp<<std::endl;

        pos = tmp.find(" ");
        std::string Text = tmp.substr(0, pos);;//string containing the number
        unsigned long Result;//number which will contain the result
        std::stringstream convert(Text); // stringstream used for the conversion initialized with the contents of Text
        if ( !(convert >> Result) ){//give the value to Result using the characters in the string
            Result = 0;//if that fails set Result to 0
            printf("%s: cannot cast %s to number\n",__FUNCTION__, Text.c_str());
            exit(-1);
        }

        lineInfo->lineNum = Result;

        if (pos != std::string::npos){
            tmp = rawLineInfo.substr(pos); //ignore line Num.
            lineInfo->extraInfo = tmp;
        }else{
            lineInfo->extraInfo = "";
        }
        lineInfo->valid = true;
        // exit(-1);
        if (lineInfo->lineNum == 0) {
            printf("%s at %s:%d, got a 0 line number\n", __FUNCTION__, __FILE__, __LINE__);
            exit(-1);
        }
    }else{
        return -1;
    }
    return 0;
}

/* searchDebugFilesForProcName:
    - for asid with IP, search all debugfiles that can return the lineInfo for this ip.
    - debug files stored in a vector of strings
    - mark the gProcToDebugDone[procName] as done if found one available lineInfo from a file.
    - TODO: might be other ways to find debugfiles for a procName,
    -    e.g. list in the txt file statically, or search here more intelligently
*/
int searchDebugFilesForProcName(std::string procName, target_ulong ip, FileLineInfo *fileInfo){
    // search among all debug files, 
    // if there is one ip info got a valid line info, we regard it as valide debug file for this proc.
    // bool found = false;
    // printf("%s: search debug file for proc: %s\n", __FUNCTION__, procName.c_str());
    for (std::vector<std::string>::size_type i = 0; i < gDebugFiles.size(); i++){
        if (addr2line(gDebugFiles[i], ip, fileInfo) == 0){
            // found info from debugfile
            // link this debugfile with procName
            gProcToDebugFileIndex[procName] = (int) i;
            printf("%s: found debug file %s for proc %s\n", __FUNCTION__, gDebugFiles[i].c_str(), procName.c_str() );
            gProcToDebugDone[procName]=true;
            return 0;
        }
    }
    return -1;
}

/* getLineInfoForAsidIP:

    - given asid, and ip, trying to find proper debug file and call addr2line to get the line info

    - here we create and maintain a debug file vector for each asid <-> debugfiles 

*/

int getLineInfoForAsidIP(target_ulong asid_target, target_ulong ip, FileLineInfo *fileInfo){

    //1. get proc name for asid
    // gProcs;
    // gAsidToProcIndex;
    std::string procName;

    std::tr1::unordered_map<target_ulong, int>::iterator asidProcIt = gAsidToProcIndex.find(asid_target);
    if (asidProcIt != gAsidToProcIndex.end()){
        //found the proc name from asid
        procName = gProcs[asidProcIt -> second];

    }else{
        //no proc name found for asid: 
        printf("%s: no proc name found for asid: 0x" TARGET_FMT_lx "\n", __FUNCTION__, asid_target );
        return -1;
    }


    //2. get debug file for proc name
    // gProcToDebugFileIndex;
    // gDebugFiles;

    std::string debugFileName;

    // std::tr1::unordered_map<std::string, int>::iterator procDebugIt = gProcToDebugFileIndex.find(procName);
    // if (procDebugIt != gProcToDebugFileIndex.end()){
    if (gProcToDebugFileIndex.count(procName) != 0){
        //found the proc name from asid
        debugFileName = gDebugFiles[gProcToDebugFileIndex[procName]];
        printf("%s: found debug file for %s: %s\n", __FUNCTION__, procName.c_str(), debugFileName.c_str());
        // exit(-1);

    }else{
        //no proc name found for asid: 
        // try to search it if never searched.
        // TODO: might give more chances to search? like 5 chances each procName?
        
        if (! gProcToDebugDone[procName]){
           return searchDebugFilesForProcName(procName,ip,fileInfo);
        }
        // 
        printf("%s: no debug file found for proc name: %s\n", __FUNCTION__, procName.c_str() );
        return -1;
    }

    //3, iterate through all debug files for proc.
    // TODO: might be different debug file for a proc?
    // Now only 1 debug file for the proc.

    if ( addr2line(debugFileName, ip, fileInfo) == 0 ){
        return 0;
    }else{
        return -1;
    }   

}

/*
    int getFileLineInfoFinal for target_asid
    called after replay finished.
    using addr2line with debug symbol files.
    fill gAsidPCtoFileLine for each available asids.
    need to know the "asid <-> debug_symbol_file" mapping relationships (i.e. gProcToDebugFileIndex[asid])

*/
// int getFileLineInfoFinal(target_ulong target_asid){

    

//     target_ulong pc = ;

//     FileLineInfo lineInfo;

//     // if (gProcToDebugFileIndex.find(target_asid) == gProcToDebugFileIndex.end()){
//     //     // no debug file available for this asid.
//     //     return;
//     // }
//     // int rc = addr2line(gProcToDebugFileIndex[target_asid], pc, &lineInfo);

//     int rc2 = addr2line(gCurrentTargetDebugFile, pc, &lineInfo);
//     // We are not in dwarf info
//     if (rc2 == -1){
//         // printf("%s: we are not in dwarf info\n", __FUNCTION__);
//         return;
//     }


//     std::tr1::unordered_map<ADDRINT, std::tr1::unordered_map<ADDRINT, FileLineInfo *> *>::iterator asidMapIt = gAsidPCtoFileLine.find(target_asid);

//     std::tr1::unordered_map<ADDRINT, FileLineInfo *> *asidMap;

//     if (asidMapIt == gAsidPCtoFileLine.end()){
//         // no map for this asid yet, create one
//         asidMap = new std::tr1::unordered_map<ADDRINT, FileLineInfo *>;
//         gAsidPCtoFileLine[gTargetAsid] = asidMap;
//     }else{
//         asidMap = gAsidPCtoFileLine[gTargetAsid];
//     }


// }


    // Given a context node (curContext), traverses up in the chain till the root and prints the entire calling context 
    
    VOID PrintFullCallingContext(ContextNode * curContext){
#ifdef MULTI_THREADED        
        int root;
#endif         //end MULTI_THREADED
        // set sig handler
        //struct sigaction old;
        //sigaction(SIGSEGV,&gSigAct,&old);
            
        // CallStack callstack = {0};
        // callstack.n = get_callers(callstack.callers, MAX_CCT_PRINT_DEPTH, env);
        // callstack.pc = p.pc;
        // callstack.asid = p.cr3;

        int depth = 0;

        // Dont print if the depth is more than MAX_CCT_PRINT_DEPTH since files become too large
        while(curContext && (depth ++ < MAX_CCT_PRINT_DEPTH )){     
            target_ulong con_pc = curContext->address;       
            if(IsValidIP(con_pc)){
                fprintf(gTraceFile, "\n!pc: 0x" TARGET_FMT_lx, con_pc);
                std::string file, func;
                unsigned long line;
                //printf("get source location\n");
                panda_GetSourceLocation(con_pc,  &line,&file, &func);
                fprintf(gTraceFile,"\t%s:%lu: %s",file.c_str(),line, func.c_str());                                    

                // check whether we have func/file/line info:                  
                // std::tr1::unordered_map<ADDRINT, std::tr1::unordered_map<ADDRINT, FileLineInfo *> *>::iterator asidMapIt = gAsidPCtoFileLine.find(gTargetAsid);

                // std::tr1::unordered_map<ADDRINT, FileLineInfo *> *asidMap;
                // if (asidMapIt == gAsidPCtoFileLine.end()){
                //     // no map for this asid.
                //     fprintf(gTraceFile, "\tno map for asid: 0x" TARGET_FMT_lx "\n", gTargetAsid);
                // }else{
                //     //map exists, get the map and find the file/line/func info for this pc.
                //     asidMap = gAsidPCtoFileLine[gTargetAsid];
                //     std::tr1::unordered_map<ADDRINT, FileLineInfo *>::iterator lineForPcIt = (*asidMap).find(con_pc);
                //     FileLineInfo *lineForPc;
                //     if (lineForPcIt == (*asidMap).end()){
                //         fprintf(gTraceFile, "\tno FileLineInfo for this pc");
                //     }else{
                //         lineForPc = (*asidMap)[con_pc];
                //         fprintf(gTraceFile, "\tfunc: %s, file: %s: %lu",
                //             lineForPc->funName.c_str(),
                //             lineForPc->fileName.c_str(), 
                //             lineForPc->lineNum);
                //     }
                // }
            }
#ifndef MULTI_THREADED 
            else if (curContext == gRootContext){
                fprintf(gTraceFile, "\nROOT_CTXT");	
            }
#else //MULTI_THREADED
            else if ( (root=IsARootContextNode(curContext)) != -1){
                fprintf(gTraceFile, "\nROOT_CTXT_THREAD %d", root);	
            } 
#endif //end  ifndef MULTI_THREADED            
            else if (curContext->address == 0){
                fprintf(gTraceFile, "\nIND CALL");	
            } else{
                fprintf(gTraceFile, "\nBAD IP ");	
            }
            curContext = curContext->parent;
        }
        //reset sig handler
        //sigaction(SIGSEGV,&old,0);
    }



    // Returns true of the given ContextNode is in memset() function
    int IsInMemset(ContextNode * curContext){
        int retVal = 0;
        
        // set sig handler
        //struct sigaction old;
        //sigaction(SIGSEGV,&gSigAct,&old);
        if(curContext){
            if(IsValidIP(curContext->address)){
                //lele: TODO: check func name, 'mem_set'
                // std::string fun = PIN_UndecorateSymbolName(RTN_FindNameByAddress(curContext->address),UNDECORATION_COMPLETE);
                // std::string sub = "memset";
                // if(fun == ".plt"){
                //     if(setjmp(env) == 0) {
                        
                //         if(IsValidPLTSignature(curContext) ) {
                //             target_ulong nextByte = (target_ulong) curContext->address + 2;
                //             int * offset = (int*) nextByte;
                            
                //             target_ulong nextInst = (target_ulong) curContext->address + 6;
                //             ADDRINT loc = *((target_ulong *)(nextInst + *offset));
                //             if(IsValidIP(loc)){
                //                 std::string s = PIN_UndecorateSymbolName(RTN_FindNameByAddress(loc),UNDECORATION_COMPLETE);
                //                 retVal = EndsWith(s, sub);
                //             }
                //         } 
                        
                //     }
                // } else if (EndsWith(fun,sub)){
                //     retVal = true;
                // }
            } 
        }
        //reset sig handler
        //sigaction(SIGSEGV,&old,0);
        return retVal;
    }
    


    // Given the DeadInfo data, prints the two Calling contexts
    VOID PrintCallingContexts(const DeadInfo & di){
        fprintf(gTraceFile,"\n-------------------------------------------------------\n");
        PrintFullCallingContext((ContextNode *) di.firstIP);
        fprintf(gTraceFile,"\n***********************\n");
        PrintFullCallingContext((ContextNode *)di.secondIP);
        fprintf(gTraceFile,"\n-------------------------------------------------------\n");
    }
    
    
#ifdef TESTING_BYTES
    // Prints the collected statistics on writes along with their sizes and dead/killing writes and their sizes
    inline VOID PrintInstructionBreakdown(){
        fprintf(gTraceFile,"\n " TARGET_FMT_lx ", " TARGET_FMT_lx ", " TARGET_FMT_lx ", " TARGET_FMT_lx " ",g1ByteWriteInstrCount, gFullyKilling1, gPartiallyKilling1, gPartiallyDeadBytes1);
        fprintf(gTraceFile,"\n " TARGET_FMT_lx ", " TARGET_FMT_lx ", " TARGET_FMT_lx ", " TARGET_FMT_lx " ",g2ByteWriteInstrCount, gFullyKilling2, gPartiallyKilling2, gPartiallyDeadBytes2);
        fprintf(gTraceFile,"\n " TARGET_FMT_lx ", " TARGET_FMT_lx ", " TARGET_FMT_lx ", " TARGET_FMT_lx " ",g4ByteWriteInstrCount, gFullyKilling4, gPartiallyKilling4, gPartiallyDeadBytes4);
        fprintf(gTraceFile,"\n " TARGET_FMT_lx ", " TARGET_FMT_lx ", " TARGET_FMT_lx ", " TARGET_FMT_lx " ",g8ByteWriteInstrCount, gFullyKilling8, gPartiallyKilling8, gPartiallyDeadBytes8);
        fprintf(gTraceFile,"\n " TARGET_FMT_lx ", " TARGET_FMT_lx ", " TARGET_FMT_lx ", " TARGET_FMT_lx " ",g10ByteWriteInstrCount, gFullyKilling10, gPartiallyKilling10, gPartiallyDeadBytes10);
        fprintf(gTraceFile,"\n " TARGET_FMT_lx ", " TARGET_FMT_lx ", " TARGET_FMT_lx ", " TARGET_FMT_lx " ",g16ByteWriteInstrCount, gFullyKilling16, gPartiallyKilling16, gPartiallyDeadBytes16);        
        fprintf(gTraceFile,"\n " TARGET_FMT_lx ", " TARGET_FMT_lx ", " TARGET_FMT_lx ", " TARGET_FMT_lx ", " TARGET_FMT_lx " ",gLargeByteWriteInstrCount,  gFullyKillingLarge, gPartiallyKillingLarge, gLargeByteWriteByteCount, gPartiallyDeadBytesLarge);        
    }
#endif //end TESTING_BYTES
        

#ifdef GATHER_STATS
    inline void PrintStats(
#ifdef IP_AND_CCT
                           std::list<DeadInfoForPresentation> & deadList,
#else // no IP_AND_CCT
                           std::list<DeadInfo> & deadList,
#endif  // end IP_AND_CCT
                           target_ulong deads){
#ifdef IP_AND_CCT        
        std::list<DeadInfoForPresentation>::iterator it = deadList.begin();
#else //no IP_AND_CCT        
        std::list<DeadInfo>::iterator it = deadList.begin();
#endif //end IP_AND_CCT        
        target_ulong bothMemsetContribution = 0;
        target_ulong bothMemsetContexts = 0;
        target_ulong singleMemsetContribution = 0;
        target_ulong singleMemsetContexts = 0;
        target_ulong runningSum = 0;
        int curContributionIndex = 1;
        
        target_ulong deadCount = 0;
        for (; it != deadList.end(); it++) {
            deadCount++;
#ifdef IP_AND_CCT        
            int memsetVal = IsInMemset(it->pMergedDeadInfo->context1);
            memsetVal += IsInMemset(it->pMergedDeadInfo->context2);
#else //no IP_AND_CCT
            int memsetVal = IsInMemset((ContextNode*) it->firstIP);
            memsetVal += IsInMemset((ContextNode*) it->secondIP);
#endif //end IP_AND_CCT            
            if(memsetVal == 2){
                bothMemsetContribution += it->count;	
                bothMemsetContexts++;
            } else if (memsetVal > 0){
                singleMemsetContribution += it->count;	
                singleMemsetContexts++;
            }
            
            runningSum += it->count;
            double contrib = runningSum * 100.0 / gTotalDead;
            if(contrib >= curContributionIndex){
                while(contrib >= curContributionIndex){
                    fprintf(statsFile,", " TARGET_FMT_lx ":%e",deadCount, deadCount * 100.0 / deads);
                    curContributionIndex++;
                }	
            }
        }
        static bool firstTime = true;
        if(firstTime){
            fprintf(statsFile,"\nbothMemsetContribution  " TARGET_FMT_lx " = %e", bothMemsetContribution, bothMemsetContribution * 100.0 / gTotalDead);
            fprintf(statsFile,"\nsingleMemsetContribution  " TARGET_FMT_lx " = %e", singleMemsetContribution, singleMemsetContribution * 100.0 / gTotalDead);
            fprintf(statsFile,"\nbothMemsetContext  " TARGET_FMT_lx " = %e", bothMemsetContexts, bothMemsetContexts * 100.0 / deads);
            fprintf(statsFile,"\nsingleMemsetContext  " TARGET_FMT_lx " = %e", singleMemsetContexts, singleMemsetContexts * 100.0 / deads);
            fprintf(statsFile,"\nTotalDeadContexts  " TARGET_FMT_lx "", deads);
            firstTime = false;
        }        
    }
#endif //end GATHER_STATS    
    
    

inline target_ulong GetMeasurementBaseCount(){
        // byte count
        
#ifdef MULTI_THREADED        
        printf("MULTI_THREAD: computing base count\n");
        target_ulong measurementBaseCount =  GetTotalNByteWrites(1) + 2 * GetTotalNByteWrites(2) + 4 * GetTotalNByteWrites(4) + 8 * GetTotalNByteWrites(8) + 10 * GetTotalNByteWrites(10)+ 16 * GetTotalNByteWrites(16) + GetTotalNByteWrites(-1);
#else //no MULTI_THREADED        
        printf("NO MULTI_THREADED: computing base count.\n");
        printf("1: " TARGET_FMT_lu ";2: " TARGET_FMT_lu ";4 " TARGET_FMT_lu ";8: " TARGET_FMT_lu ";10: " TARGET_FMT_lu ";16: " TARGET_FMT_lu ";large: " TARGET_FMT_lu "\n",
          g1ByteWriteInstrCount, g2ByteWriteInstrCount,
          g4ByteWriteInstrCount, g8ByteWriteInstrCount,
          g10ByteWriteInstrCount,g16ByteWriteInstrCount,
          gLargeByteWriteInstrCount);
        target_ulong measurementBaseCount =  g1ByteWriteInstrCount + 2 * g2ByteWriteInstrCount + 4 * g4ByteWriteInstrCount + 8 * g8ByteWriteInstrCount + 10 * g10ByteWriteInstrCount + 16 * g16ByteWriteInstrCount + gLargeByteWriteInstrCount;
#endif  //end MULTI_THREADED
        printf("%s: base count  " TARGET_FMT_lu "\n",__FUNCTION__, measurementBaseCount);
        return measurementBaseCount;        
    }

    // Prints the collected statistics on writes along with their sizes
    inline void PrintEachSizeWrite(){
        printf("now in func: %s\n", __FUNCTION__);
#ifdef MULTI_THREADED
        fprintf(gTraceFile,"\n1: " TARGET_FMT_lu "",GetTotalNByteWrites(1));
        fprintf(gTraceFile,"\n2: " TARGET_FMT_lu "",GetTotalNByteWrites(2));
        fprintf(gTraceFile,"\n4: " TARGET_FMT_lu "",GetTotalNByteWrites(4));
        fprintf(gTraceFile,"\n8: " TARGET_FMT_lu "",GetTotalNByteWrites(8));
        fprintf(gTraceFile,"\n10: " TARGET_FMT_lu "",GetTotalNByteWrites(10));
        fprintf(gTraceFile,"\n16: " TARGET_FMT_lu "",GetTotalNByteWrites(16));
        fprintf(gTraceFile,"\nother: " TARGET_FMT_lu "",GetTotalNByteWrites(-1));
        
#else  //no MULTI_THREADED        
        fprintf(gTraceFile,"\n1: " TARGET_FMT_lu "",g1ByteWriteInstrCount);
        fprintf(gTraceFile,"\n2: " TARGET_FMT_lu "",g2ByteWriteInstrCount);
        fprintf(gTraceFile,"\n4: " TARGET_FMT_lu "",g4ByteWriteInstrCount);
        fprintf(gTraceFile,"\n8: " TARGET_FMT_lu "",g8ByteWriteInstrCount);
        fprintf(gTraceFile,"\n10: " TARGET_FMT_lu "",g10ByteWriteInstrCount);
        fprintf(gTraceFile,"\n16: " TARGET_FMT_lu "",g16ByteWriteInstrCount);
        fprintf(gTraceFile,"\nother: " TARGET_FMT_lu "",gLargeByteWriteInstrCount);
#endif //end MULTI_THREADED
        printf("func: %s: done\n", __FUNCTION__);
    }
    
#ifdef IP_AND_CCT  
    // Given a pointer (i.e. slot) within a trace node, returns the IP corresponding to that slot
    // Lele: Given a pointer TODO: 
    //  within a trace node, returns the IP corresponding to that slot
    //inline ADDRINT GetIPFromInfo(void * ptr){
    inline ADDRINT GetIPFromInfo(void * ptr){
        //lele: use ContextNode->address as key instead of BlockNode
		BlockNode * traceNode = *((BlockNode **) ptr);
        // ContextNode * contextNode = (ContextNode *) ptr;
        
		// what is my slot id ?
		uint32_t slotNo = 0;
		for( ; slotNo < traceNode->nSlots; slotNo++){
		// for( ; slotNo < contextNode->nSlots; slotNo++){
			if (&traceNode->childIPs[slotNo] == (BlockNode **) ptr)
				break;
		}
        
		ADDRINT *ip = (ADDRINT *) gBlockShadowMap[traceNode->address] ;
		return ip[slotNo];
	}
    
    void  panda_GetSourceLocation(ADDRINT ip, unsigned long *line, std::string *file, std::string *func){
        //Lele: given IP, return the line number and file
        // printf("Now in %s for asid: 0x" TARGET_FMT_lx ", ip: 0x" TARGET_FMT_lx "\n",
        //     __FUNCTION__, target_asid, ip);
        
        // std::tr1::unordered_map<ADDRINT, std::tr1::unordered_map<ADDRINT, FileLineInfo *> *>::iterator asidMapIt = gAsidPCtoFileLine.find(target_asid);

        target_ulong target_asid = gTargetAsid;
        target_ulong target_asid_st = gTargetAsid_struct;

        std::tr1::unordered_map<ADDRINT, FileLineInfo *> *asidMap;

        // find line info from gAsidPCtoFileLine 

        if (gAsidPCtoFileLine.count(target_asid) != 0){
            // map exists for this asid, get the map

            asidMap = gAsidPCtoFileLine[target_asid];
            // std::tr1::unordered_map<ADDRINT, FileLineInfo *>::iterator lineForPcIt = (*asidMap).find(ip);
            FileLineInfo *lineForPc_ptr;
            // if (lineForPcIt == (*asidMap).end()){
            if ((*asidMap).count(ip) != 0){

                // line info exists in *asidMap, check whether changes
                lineForPc_ptr = (*asidMap)[ip];
                *line = lineForPc_ptr->lineNum;
                *file = lineForPc_ptr->fileName;
                *func = lineForPc_ptr->funName;
                // printf("%s: get line info from gAsidPCtoFileLine map. ip: 0x" TARGET_FMT_lx ": %s at %s:%lu\n",
                    // __FUNCTION__, ip, func->c_str(), file->c_str(), (*line));
                return;
            }
        }else if (gAsidPCtoFileLine.count(target_asid_st) != 0){

            asidMap = gAsidPCtoFileLine[target_asid_st];
            // std::tr1::unordered_map<ADDRINT, FileLineInfo *>::iterator lineForPcIt = (*asidMap).find(ip);
            FileLineInfo *lineForPc_ptr;
            // if (lineForPcIt == (*asidMap).end()){
            if ((*asidMap).count(ip) != 0){

                // line info exists in *asidMap, check whether changes
                lineForPc_ptr = (*asidMap)[ip];
                *line = lineForPc_ptr->lineNum;
                *file = lineForPc_ptr->fileName;
                *func = lineForPc_ptr->funName;
                // printf("%s: get line info from gAsidPCtoFileLine map. ip: 0x" TARGET_FMT_lx ": %s at %s:%lu\n",
                    // __FUNCTION__, ip, func->c_str(), file->c_str(), (*line));
                return;
            }
        }else{
            // create a map for this asid
            asidMap = new std::tr1::unordered_map<ADDRINT, FileLineInfo *>;
            gAsidPCtoFileLine[target_asid] = asidMap;
            gAsidPCtoFileLine[target_asid_st] = asidMap;
        }

        // if cannot find line info from gAsidPCtoFileLine 
        // try to use addr2line to get line info;
        // either found or not, set line info for this ip
        // store it in gAsidPCtoFileLine[asid][ip], and
        // return the values.

        FileLineInfo *lineForPc = new FileLineInfo;
            // 
        if (getLineInfoForAsidIP(target_asid, ip, lineForPc) < 0 
            && getLineInfoForAsidIP(target_asid_st, ip, lineForPc) < 0){
            // cannot find by addr2line.
            // printf("%s: WARNING: no asidMap for asid 0x" TARGET_FMT_lx "\n", __FUNCTION__, target_asid);
            lineForPc->valid = true;
            lineForPc->lineNum = 0;
            lineForPc->fileName= "debug_info_not_available";
            lineForPc->funName = "NA";
        }

        (*asidMap)[ip] = lineForPc;
        *line = lineForPc->lineNum;
        *file = lineForPc->fileName;
        *func = lineForPc->funName;
        printf("%s: get line info from addr2line. ip: 0x" TARGET_FMT_lx ": %s at %s:%lu\n",
                __FUNCTION__, ip, func->c_str(), file->c_str(), (*line));

    }

    // Given a pointer (i.e. slot) within a trace node, returns the Line number corresponding to that slot
	inline std::string GetLineFromInfo(void * ptr){
		ADDRINT ip = GetIPFromInfo(ptr);
        std::string file, func;
        unsigned long line;
        //PIN_GetSourceLocation(ip, NULL, &line,&file);
        panda_GetSourceLocation( ip, &line,&file, &func);
		std::ostringstream retVal;
		retVal << line;
		return file + ":" + retVal.str();
    }    
    
    
    
    // Prints the complete calling context including the line nunbers and the context's contribution, given a DeadInfo 
    inline VOID PrintIPAndCallingContexts(const DeadInfoForPresentation & di, target_ulong measurementBaseCount){
        printf("now in func: %s\n", __FUNCTION__);
        fprintf(gTraceFile,"\n " TARGET_FMT_lu " = %e",di.count, di.count * 100.0 / measurementBaseCount);
        fprintf(gTraceFile,"\n-------------------------------------------------------\n");
#ifdef MERGE_SAME_LINES
        fprintf(gTraceFile,"\n%s",di.pMergedDeadInfo->line1.c_str());                                    
#else // no MERGE_SAME_LINES
        std::string file, func;
        unsigned long line;
        //printf("get source location\n");
        panda_GetSourceLocation(di.pMergedDeadInfo->ip1,  &line,&file, &func);
        fprintf(gTraceFile,"\n%p:%s:%lu: %s",(void *)(uintptr_t)(di.pMergedDeadInfo->ip1),file.c_str(),line, func.c_str());                                    
#endif //end MERGE_SAME_LINES        
        PrintFullCallingContext(di.pMergedDeadInfo->context1);
        fprintf(gTraceFile,"\n***********************\n");
#ifdef MERGE_SAME_LINES
        fprintf(gTraceFile,"\n%s",di.pMergedDeadInfo->line2.c_str());                                    
#else //no MERGE_SAME_LINES        
        panda_GetSourceLocation(di.pMergedDeadInfo->ip2,  &line,&file, &func);
        fprintf(gTraceFile,"\n%p:%s:%lu: %s",(void *)(uintptr_t)(di.pMergedDeadInfo->ip2),file.c_str(),line, func.c_str());
#endif //end MERGE_SAME_LINES        
        PrintFullCallingContext(di.pMergedDeadInfo->context2);
        fprintf(gTraceFile,"\n-------------------------------------------------------\n");

        // printf("func: %s: done.\n", __FUNCTION__);
    }
    
    
    
    // On each Unload of a loaded image, the accummulated deadness information is dumped
    // VOID ImageUnload() {
void ExtractDeadMap(){
        printf("now in func %s. \n", __FUNCTION__);
        // Update gTotalInstCount first 
        target_ulong measurementBaseCount =  GetMeasurementBaseCount(); 
        
        fprintf(gTraceFile, "\nTotal Instr =  " TARGET_FMT_lu "", measurementBaseCount);
        printf("%s: total instr:  " TARGET_FMT_lu "\n", __FUNCTION__, measurementBaseCount);
        // make sure DeadMap is not empty:
        uint64_t mapSize = DeadMap.size();
        printf("%s: size of DeadMap: %lu\n", __FUNCTION__, mapSize);
        fprintf(gTraceFile, "\nsize of DeadMap: %lu\n", mapSize);

        fflush(gTraceFile);

        if (mapSize < 1){
            return;
        }
        
#if defined(CONTINUOUS_DEADINFO)
        //sparse_hash_map<uint64_t, uint64_t>::iterator mapIt = DeadMap.begin();
        std::tr1::unordered_map<uint64_t, uint64_t>::iterator mapIt = DeadMap.begin();
        //dense_hash_map<uint64_t, uint64_t>::iterator mapIt = DeadMap.begin();
#else //no defined(CONTINUOUS_DEADINFO)        
        dense_hash_map<uint64_t, DeadInfo>::iterator mapIt = DeadMap.begin();
        //std::tr1::unordered_map<uint64_t, DeadInfo>::iterator mapIt = DeadMap.begin();
#endif //end defined(CONTINUOUS_DEADINFO)        
        std::map<MergedDeadInfo,uint64_t> mergedDeadInfoMap;
        
        printf("%s: get Header of the DeadMap: 0x%lx \n",__FUNCTION__,mapIt->first);
#if defined(CONTINUOUS_DEADINFO)
        printf("%s: continuous\n", __FUNCTION__);
        for (; mapIt != DeadMap.end(); mapIt++) {
            MergedDeadInfo tmpMergedDeadInfo;
            uint64_t hash = mapIt->first;
	        // printf("%s: read one dead info: hash: 0x%lx\n", __FUNCTION__, hash);
            BlockNode ** ctxt1 = (BlockNode **)(gPreAllocatedContextBuffer + (hash >> 32));
            // printf("get ctxt1: %p, ", ctxt1);
            // printf(" *ctxt1: %p\n", *ctxt1);
	        BlockNode ** ctxt2 = (BlockNode **)(gPreAllocatedContextBuffer + (hash & 0xffffffff));
            // printf("get ctxt2: %p, *ctxt2: %p\n", ctxt2, *ctxt2);
            // printf("get ctxt2: %p, *ctxt2: %p\n", ctxt2, *ctxt2);
            
            tmpMergedDeadInfo.context1 = (*ctxt1)->parent;
	        // printf("get context1: %p\n", tmpMergedDeadInfo.context1);
            tmpMergedDeadInfo.context2 = (*ctxt2)->parent;
            // printf("get context2: %p\n", tmpMergedDeadInfo.context2);

#ifdef MERGE_SAME_LINES
            tmpMergedDeadInfo.line1 = GetLineFromInfo(ctxt1);
            tmpMergedDeadInfo.line2 = GetLineFromInfo(ctxt2);
#else  //no MERGE_SAME_LINES            
            tmpMergedDeadInfo.ip1 = GetIPFromInfo(ctxt1);
            tmpMergedDeadInfo.ip2 = GetIPFromInfo(ctxt2);
#endif //end MERGE_SAME_LINES            
            std::map<MergedDeadInfo,uint64_t>::iterator tmpIt;
            if( (tmpIt = mergedDeadInfoMap.find(tmpMergedDeadInfo)) == mergedDeadInfoMap.end()) {
                mergedDeadInfoMap[tmpMergedDeadInfo] = mapIt->second;
            } else {
                
                tmpIt->second  += mapIt->second;
            }
        }
        
	    // clear dead std::map now
        DeadMap.clear();
        
        
#else   // no defined(CONTINUOUS_DEADINFO)        

        printf("%s: NOT continuous\n", __FUNCTION__);
        for (; mapIt != DeadMap.end(); mapIt++) {
            MergedDeadInfo tmpMergedDeadInfo;
            printf("counting written bytes:  " TARGET_FMT_lx "\n", writeSize);
            tmpMergedDeadInfo.context1 = (*((BlockNode **)((mapIt->second).firstIP)))->parent;
            tmpMergedDeadInfo.context2 = (*((BlockNode **)((mapIt->second).secondIP)))->parent;
#ifdef MERGE_SAME_LINES
            tmpMergedDeadInfo.line1 = GetLineFromInfo(mapIt->second.firstIP);
            tmpMergedDeadInfo.line2 = GetLineFromInfo(mapIt->second.secondIP);
#else //no MERGE_SAME_LINES            
            tmpMergedDeadInfo.ip1 = GetIPFromInfo(mapIt->second.firstIP);
            tmpMergedDeadInfo.ip2 = GetIPFromInfo(mapIt->second.secondIP);
#endif //end MERGE_SAME_LINES            
            std::map<MergedDeadInfo,uint64_t>::iterator tmpIt;
            if( (tmpIt = mergedDeadInfoMap.find(tmpMergedDeadInfo)) == mergedDeadInfoMap.end()) {
                mergedDeadInfoMap[tmpMergedDeadInfo] = mapIt->second.count;
            } else {
                
                tmpIt->second  += mapIt->second.count;
            }
        }
        
	    // clear dead map now
        DeadMap.clear();
#endif  // end defined(CONTINUOUS_DEADINFO)        
        
        printf("%s, DeadMap cleared; got mergedDeadInfoMap. now compute DeadInfoForPresentation list\n", __FUNCTION__);
        std::map<MergedDeadInfo,uint64_t>::iterator it = mergedDeadInfoMap.begin();	
        std::list<DeadInfoForPresentation> deadList;
        for (; it != mergedDeadInfoMap.end(); it ++) {
            DeadInfoForPresentation deadInfoForPresentation;
            deadInfoForPresentation.pMergedDeadInfo = &(it->first);
            deadInfoForPresentation.count = it->second;
            deadList.push_back(deadInfoForPresentation);
        }

        printf("%s, get deadList, now sort it\n", __FUNCTION__);
        deadList.sort(MergedDeadInfoComparer);
        
	    //present and delete all
        
        printf("%s, analysis and print deadlist to file\n", __FUNCTION__);

        std::list<DeadInfoForPresentation>::iterator dipIter = deadList.begin();
        //PIN_LockClient();
        target_ulong deads = 0;
        for (; dipIter != deadList.end(); dipIter++) {
#ifdef MULTI_THREADED
            assert(0 && "NYI");    
#endif //end MULTI_THREADED            
            // Print just first MAX_DEAD_CONTEXTS_TO_LOG contexts
            if(deads < MAX_DEAD_CONTEXTS_TO_LOG){
                try{
                    PrintIPAndCallingContexts(*dipIter, measurementBaseCount);
                } catch (...) {
                    fprintf(gTraceFile,"\nexcept");
                }
            } else {
                // print only dead count
#ifdef PRINT_ALL_CTXT
                fprintf(gTraceFile,"\nCTXT_DEAD_CNT: " TARGET_FMT_lu " = %e",dipIter->count, dipIter->count * 100.0 / measurementBaseCount);
#endif                //end PRINT_ALL_CTXT
            }
            
            gTotalDead += dipIter->count ;
            deads++;
        }
        
        printf("%s: done print deadList; then print each size write.\n", __FUNCTION__);

        PrintEachSizeWrite();
        
#ifdef TESTING_BYTES
        PrintInstructionBreakdown();
#endif //end TESTING_BYTES        
        
#ifdef GATHER_STATS
        PrintStats(deadList, deads);
#endif //end GATHER_STATS        
        
        mergedDeadInfoMap.clear();
        deadList.clear();
        printf("%s: mergedDeadInfoMap and deadList cleared.\n", __FUNCTION__);
        printf("%s: size of DeadMap: %lu\n", __FUNCTION__, mapSize);
        //PIN_UnlockClient();

        printf("%s: Done.\n", __FUNCTION__);
	}
    
#else //no IP_AND_CCT
    // On each Unload of a loaded image, the accummulated deadness information is dumped (JUST the CCT case, no IP)
    // VOID ImageUnload() {
void ExtractDeadMap(){
        // fprintf(gTraceFile, "\nUnloading %s", IMG_Name(img).c_str());
        fprintf(gTraceFile, "\nUnloading");
        //static bool done = false;
        bool done = false;
        //if (done)
        //    return;
        
        //if(IMG_Name(img) != "/opt/apps/openmpi/1.3.3-gcc/lib/openmpi/mca_osc_rdma.so")
        //if(IMG_Name(img) != "/users/mc29/mpi_dead/Gauss.exe")
        //if(IMG_Name(img) != "/users/mc29/chombo/chombo/Chombo-4.petascale/trunk/benchmark/AMRGodunovFBS/exec/amrGodunov3d.Linux.64.mpicxx.mpif90.OPTHIGH.MPI.ex")
        //return;
        
        // get  measurementBaseCount first 
        target_ulong measurementBaseCount =  GetMeasurementBaseCount();         
        fprintf(gTraceFile, "\nTotal Instr =  " TARGET_FMT_lu "", measurementBaseCount);
        printf("get total Instr:  " TARGET_FMT_lu "\n", measurementBaseCount);
        fflush(gTraceFile);
        
#if defined(CONTINUOUS_DEADINFO)
        std::tr1::unordered_map<uint64_t, uint64_t>::iterator mapIt;
        //dense_hash_map<uint64_t, uint64_t>::iterator mapIt;
        //sparse_hash_map<uint64_t, uint64_t>::iterator mapIt;
#else // no defined(CONTINUOUS_DEADINFO)        
        dense_hash_map<uint64_t, DeadInfo>::iterator mapIt;
        //std::tr1::unordered_map<uint64_t, DeadInfo>::iterator mapIt;
#endif  //end defined(CONTINUOUS_DEADINFO)        
        std::list<DeadInfo> deadList;
        
        
#if defined(CONTINUOUS_DEADINFO)
        for (mapIt = DeadMap.begin(); mapIt != DeadMap.end(); mapIt++) {
            uint64_t = mapIt->first;
            uint64_t elt1 = (hash >> 32) * sizeof(void **) / sizeof(ContextNode);
            uint64_t elt2 = (hash & 0xffffffff) * sizeof(void **) / sizeof(ContextNode);
            void ** ctxt1 = (void**) ((ContextNode*)gPreAllocatedContextBuffer + elt1);
            void ** ctxt2 = (void**)((ContextNode*)gPreAllocatedContextBuffer + elt2);
            DeadInfo tmpDeadInfo = {(void*)ctxt1, (void*)ctxt2,  mapIt->second};
            deadList.push_back(tmpDeadInfo);
        }
        DeadMap.clear();
        
#else   // no defined(CONTINUOUS_DEADINFO)        
        for (mapIt = DeadMap.begin(); mapIt != DeadMap.end(); mapIt++) {
            deadList.push_back(mapIt->second);
        }
        DeadMap.clear();
#endif  // end defined(CONTINUOUS_DEADINFO)        
        deadList.sort(DeadInfoComparer);
        std::list<DeadInfo>::iterator it = deadList.begin();
        PIN_LockClient();
        target_ulong deads = 0;
        for (; it != deadList.end(); it++) {
            
#ifdef MULTI_THREADED
            // for MT, if they are from the same CCT, skip
            if(IsSameContextTree((ContextNode*) it->firstIP, (ContextNode*)it->secondIP)){
            	gTotalDead += it->count ;
                continue;
            } 
#endif //end MULTI_THREADED            
            
            // Print just first MAX_DEAD_CONTEXTS_TO_LOG contexts
            if(deads < MAX_DEAD_CONTEXTS_TO_LOG){
                try{
                    fprintf(gTraceFile,"\n " TARGET_FMT_lu " = %e",it->count, it->count * 100.0 / measurementBaseCount);
                    PrintCallingContexts(*it);
                } catch (...) {
                    fprintf(gTraceFile,"\nexcept");
                }
            } else {
#ifdef PRINT_ALL_CTXT
                // print only dead count
                fprintf(gTraceFile,"\nCTXT_DEAD_CNT: " TARGET_FMT_lu " = %e",it->count, it->count * 100.0 / measurementBaseCount);
#endif //end PRINT_ALL_CTXT                
            }
            
#ifdef MULTI_THREADED
            gTotalMTDead += it->count ;
#endif //end MULTI_THREADED            
            gTotalDead += it->count ;
            deads++;
        }
        
        PrintEachSizeWrite();
        
        
#ifdef TESTING_BYTES
        PrintInstructionBreakdown();
#endif //end TESTING_BYTES        
        
#ifdef GATHER_STATS
        PrintStats(deadList, deads);
#endif //end GATHER_STATS        
        
        deadList.clear();
        // PIN_UnlockClient();
        done = true;
        printf("%s: done.\n", __FUNCTION__);
    }

#endif   //end IP_AND_CCT    

    
    
// On program termination output all gathered data and statistics
// VOID Fini(int32_t code, VOID * v) {
VOID Fini() {
    // byte count
    target_ulong measurementBaseCount = GetMeasurementBaseCount();
    fprintf(gTraceFile, "\n#deads");
    fprintf(gTraceFile, "\nGrandTotalWrites =  " TARGET_FMT_lu "",measurementBaseCount);
    fprintf(gTraceFile, "\nGrandTotalDead =  " TARGET_FMT_lu " = %e%%",gTotalDead, gTotalDead * 100.0 / measurementBaseCount);
#ifdef MULTI_THREADED        
    fprintf(gTraceFile, "\nGrandTotalMTDead =  " TARGET_FMT_lu " = %e%%",gTotalMTDead, gTotalMTDead * 100.0 / measurementBaseCount);
#endif // end MULTI_THREADED        
    fprintf(gTraceFile, "\n#eof");
    fclose(gTraceFile);
}

VOID printAllProcsFound(){
    // Iterate Over the Unordered Set and display it
    printf("%s: All Procs Found:\n", __FUNCTION__);
    std::unordered_set<ProcID>::iterator it;
    for (it = gRunningProcs.begin(); it != gRunningProcs.end(); ++it)
    {
        // u_long f = *it; // Note the "*" here
		printf("\t0x" TARGET_FMT_lx ": procName: %s\n", 
            it->proc->asid, it->proc->name);
    }
    printf("\n");
    printf("%s: (last) monitored ASID:\n", __FUNCTION__);
    if (gAsidToProcIndex.count(gTargetAsid) != 0 ){
        printf("\t0x" TARGET_FMT_lx ": procName: %s\n", gTargetAsid, gProcs[gAsidToProcIndex[gTargetAsid]].c_str());
    }
    if (gAsidToProcIndex.count(gTargetAsid_struct) != 0){
        printf("\t(struct): 0x" TARGET_FMT_lx ": procName: %s\n", gTargetAsid, gProcs[gAsidToProcIndex[gTargetAsid_struct]].c_str());
    }
    if (gAsidToProcIndex.count(gTargetAsid_struct) == 0 && gAsidToProcIndex.count(gTargetAsid) == 0 ){
        printf("\t no proc found for 0x" TARGET_FMT_lx ", (struct): 0x" TARGET_FMT_lx "\n", gTargetAsid, gTargetAsid_struct);
    }
}
// done last step: printing

//#########################


//###########################
// Lele: use capstone to disasemble instructions after transalte the block
// Refer: callstack_instr
// - based on callstack_instr to detect call and ret
// - and also store each instr IP for each basic block., as an alternative of Traces in PIN
// - TODO: ? also tracking function stacks.


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
        printf("%s: i386 arch.\n", __FUNCTION__);
        if (cs_open(CS_ARCH_X86, CS_MODE_32, &csh_hd_32) != CS_ERR_OK)
        #if defined(TARGET_X86_64)
            printf("%s: x86_64 arch.\n", __FUNCTION__);
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &csh_hd_64) != CS_ERR_OK)
        #endif
    #elif defined(TARGET_ARM)
        printf("%s: ARM arch.\n", __FUNCTION__);
        if (cs_open(CS_ARCH_ARM, CS_MODE_32, &csh_hd_32) != CS_ERR_OK)
    #elif defined(TARGET_PPC)
        printf("%s: PPC arch.\n", __FUNCTION__);
        if (cs_open(CS_ARCH_PPC, CS_MODE_32, &csh_hd_32) != CS_ERR_OK)
    #endif
         {
            printf("ERROR initializing capstone\n");
            return ;
         }   

        // Need details in capstone to have instruction groupings
        if (cs_option(csh_hd_32, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK){
            printf("ERROR cs_option 32 bit\n");
            return ;
        }
    #if defined(TARGET_X86_64)
        if (cs_option(csh_hd_64, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK){
            printf("ERROR cs_optin for x86_64\n");
            return ;
        }
    #endif

    init_capstone_done = true;
}

//
//

ins_type disas_block_dw(CPUArchState* env, target_ulong pc, int size) {
    unsigned char *buf = (unsigned char *) malloc(size);
    int err = panda_virtual_memory_rw(ENV_GET_CPU(env), pc, buf, size, 0);
    if (err != 0) printf("Couldn't read TB memory!\n");
    ins_type res = INSTR_UNKNOWN;

#if defined(TARGET_I386)
    csh handle = (env->hflags & HF_LMA_MASK) ? csh_hd_64 : csh_hd_32;
#elif defined(TARGET_ARM) || defined(TARGET_PPC)
    csh handle = csh_hd_32;
#endif
    // csh handle;
    
    // if (get_capstone_handle((CPUArchState *)env, &handle)<0){
    //     printf("%s: cannot get capstone handle from callstack_instr\n", __FUNCTION__);
    //     exit(-1);
    // }

    cs_insn *insn;
    cs_insn *end;
    size_t count = cs_disasm(handle, buf, size, pc, 0, &insn);

    // tb_insns_count[pc] = count;
    // tb_insns[pc]=insn;

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
        printf("%s: no disasm result for TB %p\n", __FUNCTION__, (void*)(uintptr_t)pc);
        goto done2;
    }

    for (end = insn + count - 1; end >= insn; end--) {
        if (!cs_insn_group(handle, end, CS_GRP_INVALID)) {
            break;
        }
    }
    if (end < insn) {
        printf("%s:No available instruction disasembled\n", __FUNCTION__);
        goto done;
    }

    //iterate all instructions inside this block
    // printf("%s: a block disasembled: pc=%p\n",__FUNCTION__, (void *)(uintptr_t)pc);
    // cs_insn *tmp;
    // for (tmp=insn; tmp <= end; tmp ++){
    //     printf("%s: insn: <addr,size,mnemonic,op_str> = <%p, %d, %s, %s>\n",__FUNCTION__,(void *)(uintptr_t)tmp->address,tmp->size,tmp->mnemonic, tmp->op_str);
    // }

    if (pc != insn->address){
        printf("block address is not equal to its first intruction's address!!!\n");
        exit(-1);
    }
    
    if (cs_insn_group(handle, end, CS_GRP_CALL)) {
        res = INSTR_CALL;
        // printf("%s: detect a call\n", __FUNCTION__);
    } else if (cs_insn_group(handle, end, CS_GRP_RET)) {
        res = INSTR_RET;
        // printf("%s: detect a ret\n", __FUNCTION__);
    } else if (cs_insn_group(handle, end, CS_GRP_INT)){
        res = INSTR_INT;
        printf("%s: detect a interrupt\n", __FUNCTION__);
    } else if (cs_insn_group(handle, end, CS_GRP_IRET)){
        res = INSTR_IRET;
        printf("%s: detect a interrupt return\n", __FUNCTION__);
    } else {
        res = INSTR_UNKNOWN;
    }

done:
    //printf("don't free insn, store it in gBlockShadowMap");
    //printf("");
    cs_free(insn, count);
done2:
    free(buf);
    return res;
}

/*
InitializeBlockShadowMap()
    // create the gBlockShadowMap for a basic block. This can be called at the time of :
    //  - newly translated basic block,
    //  - newly executed basic block,
    //  - old basic block, but has larger size detected in before block execution, if so, the map is replaced.

    Key features of the map:
    //  - only one pair stored in gBlockShadowMap for one basic block with tb->pc as key.
    //  - initialized here but filled at mem_callback during block exe
    //  - might be filled during different iterations of block exe, since for same block, block exe could have different mem behaviors.
    //    --> we use gBlockShadowIPtoSlot to track whether we have an IP in the gBlockShadowMap, if we have, no need to update gBlockShadowMap, if not, we'll update it.
    //    --> So we don't use gBlockShadowMapDone to indicate whether we need to udpate gBlockShadowMap anymore. We only use this to trigger the checking of gBlockShadowIPtoSlot.

    //  - for a new Translation of the previously translated block, we will compare its size with the older translated version, store the larger size as the final.
*/
inline void InitializeBlockShadowMap(CPUState *cpu, TranslationBlock *tb){

    bool needUpdate=false;
    bool replaced=false;

    target_ulong * oldTraceShadowIP = (target_ulong *) gBlockShadowMap[tb->pc];
    std::tr1::unordered_map <ADDRINT, int > * ipToSlot = (std::tr1::unordered_map <ADDRINT, int > *) gBlockShadowIPtoSlot[tb->pc];

    target_ulong oldBlockSize = 0;

    // if oldTraceShadowIP exists, this means we already have one created before.
    // implying it has been translated before.
    // so check its new size with the older one, replace a new Shadow if size is bigger.
    if (oldTraceShadowIP){
        // printf("%s: an old basic block, now check its size\n",__FUNCTION__);

        oldBlockSize = oldTraceShadowIP[-2]; // present one behind
        // printf("%s: get block size  %d, from gBlockShadowMap[0x" TARGET_FMT_lx "][-2]\n",
        //     __FUNCTION__, (int)oldBlockSize, tb->pc);

        if (tb->size > oldBlockSize){
            printf("%s: WARNING: old block with a bigger tb size, update TraceShadowMap for tb->pc: 0x"
             TARGET_FMT_lx "\n", __FUNCTION__, tb->pc);
            needUpdate=true;
            replaced=true;
        }

    }else{
        //printf("%s: a new translated block, need update its shadowMap\n", __FUNCTION__);
        needUpdate=true;
    }


    if(needUpdate){

        // ##############################################
        // set new basic block flag; used in after block exe to set gShadowMap as done.
        gNewBasicBlock=true;

       
        // #############################################
        // create and initial gBlockShadowMap()
        //Refer: PopulateIPReverseMapAndAccountTraceInstructions()
        // - PopulateIPReverseMapAndAccountTraceInstructions(): 
        //     - Instruction() -> ManageCallingContext() on every Instruction in 
        //         - GoUpCallChain
        //     - build ipShadow before code run. (Allocated here but filled during run. (mem_callback, have size and R/W)
        //     - get write size and insert statement InstructionContributionOfBBL2Byte to count total write size.(mem_callback, have size and R/W)
        // printf("%s: create and initial gBlockShadowMap for a new basic block: tb->pc: 0x" TARGET_FMT_lx "\n", __FUNCTION__, tb->pc);

        uint32_t traceSize = tb->size;    
        ADDRINT * ipShadow = (ADDRINT * )malloc( (2 + traceSize) * sizeof(ADDRINT)); // +1 to hold the number of slots as a metadata
        ADDRINT  traceAddr = tb->pc;
        uint32_t slot = 0;
        
        // give space to account for nSlots which we record later once we know nWrites
        ADDRINT * pTraceSize = ipShadow;
        ipShadow ++;
        *pTraceSize = traceSize;

        ADDRINT * pNumWrites = ipShadow;
        ipShadow ++;
        *pNumWrites = slot;

        // copy and free the old BlockShadowMap if need replace
        if (replaced){

            printf("%s: WARNING: replaced shadowMap: copy and free the old BlockShadowMap[" TARGET_FMT_lx "], according to gBlockShadowIPtoSlots[tb]\n", __FUNCTION__, tb->pc);

            int copy_slots = (int)oldTraceShadowIP [-1];

            *pNumWrites = copy_slots;

            std::tr1::unordered_map <ADDRINT, int > ::iterator pcSlotIt = (* ipToSlot).begin();

            // we copy according to gBlockShadowIPtoSlots[tb], so that we keep the slot index for a PC not to be changed. If slot index changes for an old write PC, the old TraceNode relies on this will be invalidated.

            int i;
            for (i=0; pcSlotIt != (* ipToSlot).end(); ++ pcSlotIt){
                int slotForPC = pcSlotIt -> second;
                // target_ulong writePC = pcSlotIt -> first; // this should be = oldTraceShadowIP[slotForPC].
                ipShadow[slotForPC]=oldTraceShadowIP[slotForPC];
                i++;
            }

            // check the num of copied slots is equal to copy_slots.
            if (i != copy_slots ){
                printf("%s: ERROR: nSlots (%d) in oldTraceShadowIP is not equal with nSlots (%d) in gTraceShadowIPtoSlots, tb->pc: " TARGET_FMT_lx "\n", __FUNCTION__,copy_slots, i, tb->pc);
                exit(-1);
            }

            // free the oldShadowIP for the tb
            oldTraceShadowIP --;
            oldTraceShadowIP --;
            free(oldTraceShadowIP);
            // printf("%s: reset gBlockShadowMapDone[" TARGET_FMT_lx "]\n", __FUNCTION__, tb->pc);
            gBlockShadowMapDone[tb->pc]=false;
        }

        gBlockShadowMap[traceAddr] = ipShadow ;
        // Now ipShadow[-1] is NumWrites; ipShadow[-2] is TraceSize.


        //lele: gBlockShadowIPtoSlot;
        std::tr1::unordered_map<ADDRINT,int> * mapIps = new std::tr1::unordered_map<ADDRINT,int> ;
            //(std::tr1::unordered_map<ADDRINT, bool> *) malloc (sizeof(std::tr1::unordered_map<ADDRINT,bool>));
        // (*mapIps)[traceAddr]=-1;
        gBlockShadowIPtoSlot[traceAddr] = mapIps;

        // printf("%s: set gBlockShadowMapDone[0x" TARGET_FMT_lx "] as false for this block\n", __FUNCTION__, tb->pc);
        gBlockShadowMapDone[traceAddr] = false;

    }

}    
/**
//NOTE from PANDA:
after_block_translate: called after the translation of each basic block
    Callback ID: PANDA_CB_AFTER_BLOCK_TRANSLATE
    Arguments:
        CPUState *env: the current CPU state
        TranslationBlock *tb: the TB we just translated
    Return value:
        unused
    Signature:
        int (*after_block_translate)(CPUState *env, TranslationBlock *tb);

// after block translate, get instructions in each basic block, then store in gBlockShadowMap
//
//
// Lele: borrow from trace_insthist
*/
int after_block_translate(CPUState *cpu, TranslationBlock *tb) {

    // printf("\n############### Now in %s: pc=0x" TARGET_FMT_lx "\n",__FUNCTION__ , tb->pc);
    
    // for each block, different translations could be different. 
    // we here keep the lastest translation, how to keep consistent????
    // printf("%s: for each block, translations could be different. why? \n", __FUNCTION__);
    // printf("%s: for same translation, mem_callback could be different. why? \n", __FUNCTION__);
    // printf("%s: gBlockShadowMap might be not usefull across all the blocks???? how to resolve? \n", __FUNCTION__);

    //Lele: check asid.
    // target_ulong asid_cur = panda_current_asid_proc_struct(cpu);
    // if (gTraceOne){
    //     if (asid_cur != gTargetAsid){
    //         // printf("%s: ignore ASID " TARGET_FMT_lx "\n", __FUNCTION__, asid_cur);
    //         gIgnoredASIDs.insert(asid_cur);
    //         return 1;
    //     }
    //     // else{
    //     //     printf("%s: a block for target ASID: 0x" TARGET_FMT_lx "\n", __FUNCTION__, gTargetAsid);
    //     // }
    // }else if (gTraceKernel){
    //     if (asid_cur != 0x0 ){
    //         printf("%s: ignore non-kernel ASID " TARGET_FMT_lx "\n", __FUNCTION__, asid_cur);
    //         gIgnoredASIDs.insert(asid_cur);
    //         return 1;
    //     } else{
    //         printf("\n%s: kernel block\n", __FUNCTION__);
    //     }
    // }else if (gTraceApp){
    //     if (asid_cur == 0x0 ){
    //         printf("%s: ignore kernel ASID " TARGET_FMT_lx "\n", __FUNCTION__, asid_cur);
    //         gIgnoredASIDs.insert(asid_cur);
    //         return 1;
    //     } else{
    //         printf("\n%s: App block, ASID: 0x" TARGET_FMT_lx "\n", __FUNCTION__, asid_cur);
    //     }
    // }else{
    //     // no filters
    //     printf("\n%s: a block for ASID: 0x" TARGET_FMT_lx "\n", __FUNCTION__, asid_cur);
    // }

    // printf("Now in %s\n", __FUNCTION__);
    bool judge_by_struct;
    target_ulong judge_asid;
    OsiProc *judge_proc;
    bool is_target = is_target_process_running(cpu, &judge_by_struct, &judge_asid, &judge_proc);

    // print judge metric, for debug
   
    // if(judge_by_struct){

    //     printf("%s: judge by name in struct. \n",
    //         __FUNCTION__);
        // printf("\tasid: (cpu->cr3): " TARGET_FMT_lx "\n", judge_asid);
    //     //print full info of proc
    //     print_proc_info(judge_proc);
    // }
    // else{
    //     printf("%s: judge by asid: 0x" TARGET_FMT_lx ", target: 0x" TARGET_FMT_lx "\n",
    //         __FUNCTION__, judge_asid, gTargetAsid);
    // }

    if(!is_target){
        return 1;
    }

    // printf("\n%s: ---------------- a new targeted block --------------------\n", __FUNCTION__);
    
    // printf("\n%s: a new targeted block, tb->pc = 0x" TARGET_FMT_lx "\n", __FUNCTION__, tb->pc);
    
    // Refer: trace_insthist: after_block_translate

    // Refer: callstack_instr: after_block_translate(CPUState *cpu, TranslationBlock *tb)
    
    if (!init_capstone_done) init_capstone(cpu);

    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    block_cache[tb->pc] = disas_block_dw(env, tb->pc, tb->size);

    // detect the last instruction type

    ins_type tb_type = block_cache[tb->pc];
    if (tb_type == INSTR_CALL) {
        // track the function that gets called
        target_ulong pc, cs_base;
        uint32_t flags;
        // This retrieves the pc in an architecture-neutral way
        cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
        printf("%s: get a function call: <tb->pc,pc>=<%p,%p>\n", __FUNCTION__, (void *)(uintptr_t) tb->pc, (void *)(uintptr_t) pc);
        //gInitiatedCall=true;
    }else if (tb_type == INSTR_RET) {
        // track the function that gets called
        target_ulong pc, cs_base;
        uint32_t flags;
        // This retrieves the pc in an architecture-neutral way
        cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
        printf("%s: get a function ret: <tb->pc,pc>=<%p,%p>\n", __FUNCTION__, (void *)(uintptr_t) tb->pc, (void *)(uintptr_t) pc);
    }else if (tb_type == INSTR_INT) {
        // track the function that gets called
        target_ulong pc, cs_base;
        uint32_t flags;
        // This retrieves the pc in an architecture-neutral way
        cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
        printf("%s: get a interrupt call: <tb->pc,pc>=<%p,%p>\n", __FUNCTION__, (void *)(uintptr_t) tb->pc, (void *)(uintptr_t) pc);
    }else if (tb_type == INSTR_IRET) {
        // track the function that gets called
        target_ulong pc, cs_base;
        uint32_t flags;
        // This retrieves the pc in an architecture-neutral way
        cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
        printf("%s: get a interrupt ret: <tb->pc,pc>=<%p,%p>\n", __FUNCTION__, (void *)(uintptr_t) tb->pc, (void *)(uintptr_t) pc);
    }
    // else {
    //     printf("UNKNOWN instruction\n");
    // }

    // printf("%s: update gBlockShadowMap when necessary, for tb->pc: " TARGET_FMT_lx "\n", __FUNCTION__, tb->pc);

    InitializeBlockShadowMap(cpu, tb);

    return 1;
}

// Does necessary work on a trace entry (called during runtime)
// 1. Look up the current trace under the CCT node creating new if if needed.
// 2. Update global iterators and curXXXX pointers.

//Lele:  split gBlockShadowMap creating and BlockNode creating:
    
//         - a new BlockNode didn't require a new gBlockShadowMap of a basic block:
//         A basic block should have only one area stored in gBlockShadowMap, but could have multiple
//         TraceNodes stored under different ContextNode.
    
//         - instrumentBeforeBlockExe(): According flag gBlockShadowMapDone[tb->pc] to determine whether
//         There is already a gBlockShadowMap built for a basic block;


//inline void instrumentBeforeBlockExe(ADDRINT currentIp){
inline void instrumentBeforeBlockExe(CPUState *cpu, TranslationBlock *tb){

    // printf("%s: tb->pc=0x" TARGET_FMT_lx "\n", __FUNCTION__, tb->pc);

    target_ulong currentIp=tb->pc;

    // printf("%s: reset gCurrentSlot as 0\n", __FUNCTION__);
    gCurrentSlot = 0;

    // if landed due to function call, create a child context node
    // create one BlockNode each time we call a basic block under current context.
    //  - For same context Node, only one traceNode for the same basic block.
    //  - same basic block could be created under different context node.
    //  - initialized here but filled at mem_callback.

    //if( (gTraceIter = (gCurrentContext->childBlocks).find(currentIp)) != gCurrentContext->childBlocks.end()) {
    if( (gTraceIter = (gCurrentContext->childBlocks).find(currentIp)) != (gCurrentContext->childBlocks).end()) {
        // if tracenode is already exists
        // set the current Trace to the new trace
        // set the IpVector
        gNewBlockNode = false;
        // printf("%s:Trace Node already exists\n",__FUNCTION__);
        gCurrentTraceBlock = gTraceIter->second;
        // printf("%s: reset gCurrentTraceBlock for existed Node\n", __FUNCTION__);
        gCurrentTraceIpVector = gCurrentTraceBlock->childIPs;
        // printf("%s: reset gCurrentTraceIpVector to %p\n", __FUNCTION__, gCurrentTraceBlock->childIPs);
        
        // TODO: check size
        target_ulong * oldTraceShadowIP = (target_ulong *) gBlockShadowMap[tb->pc];
        target_ulong oldBlockSize = 0;
        // if oldTraceShadowIP exists, this means we already have one created before.
        // For old childBlock under current context, there should be always an oldTraceShadowIP.
        // If not, there would be an error.
        // Also, if the size of the oldTraceShadowIP is smaller then tb->size, there would be also an error.
        if (oldTraceShadowIP){
            oldBlockSize = oldTraceShadowIP[-2];
            if (tb->size > oldBlockSize){
                target_ulong asid_cur = panda_current_asid_proc_struct(cpu);
                printf("%s: ERROR: old childBlock under current context has a bigger tb size, for tb->pc: 0x" TARGET_FMT_lx ", asid=0x" TARGET_FMT_lx "\n", __FUNCTION__, tb->pc, asid_cur);
                printf("%s:\tcontext node addr:  0x" TARGET_FMT_lx "\n", __FUNCTION__, gCurrentContext->address);

                // printf("%s: WARNING: now check to relplace shadowBlock\n", __FUNCTION__);
                // InitializeBlockShadowMap(cpu, tb);
                exit(-1);
            }
        }else{
            printf("%s: ERROR: an old childBlock of current context node has no gBlockShadowMap. tb->pc=0x"
                TARGET_FMT_lx ", context addr=0x" TARGET_FMT_lx "\n", __FUNCTION__, tb->pc, gCurrentContext->address);
            exit(-1);
        }

     } else {
        //panda: if not in the current context node,  a new BasicBlock(trace) node is created.
        // create and initial new BlockNode.

        // Create new trace node and insert under the context node.

        // printf("%s: Create and initialize a new Trace node.\n",__FUNCTION__);
        gNewBlockNode = true;

        BlockNode * newChild = new BlockNode();
        newChild->parent = gCurrentContext;
        // printf("\tNew Child: set parent as %p\n", gCurrentContext);

        newChild->address = currentIp;
        // printf("\tNew Child: set address as 0x" TARGET_FMT_lx " \n", currentIp);

    	target_ulong * currentBlockShadowMap = (target_ulong *) gBlockShadowMap[currentIp];
        // printf("get currentBlockShadow  %p, from gBlockShadowMap[currentIp]\n", currentBlockShadowMap);
       

        // target_ulong recordedSlots = 0; // present one behind
        if (currentBlockShadowMap){ //Lele: TODO: use find() in the gBlockShadowMap.
             int shadowMapSize = (int)currentBlockShadowMap[-2];

            // printf("%s: gBlockShadowMap already created for tb->pc: " TARGET_FMT_lx ", tb size: %d, shadowMap size: %d\n",
            // __FUNCTION__, tb->pc, tb->size, shadowMapSize);
            if (tb->size != shadowMapSize){
                printf("%s: WARNING: shadowMap size should be equal with block size\n", __FUNCTION__);
                // exit(-1);
                printf("%s: WARNING: now check to update shadowBlock if tb size is bigger than shadowMap\n", __FUNCTION__);
                InitializeBlockShadowMap(cpu, tb);
            }

            // recordedSlots = currentBlockShadowMap[-1]; // present one behind
        }else{
            // a block not translated but appear in before_block_exe:
            // also create gBlockShadowMap for it.
            // TODO: WARNING: commented out, way too much for this case.
            // printf("%s: WARNING: creating gBlockShadowMap for a non-translated block tb->pc: " TARGET_FMT_lx ", size: %d\n",
            // __FUNCTION__, tb->pc, tb->size);
            
            InitializeBlockShadowMap(cpu, tb);
            

        }

        // create newChild->childIPs and initialize them according to Basic block size.

#ifdef CONTINUOUS_DEADINFO
        // if CONTINUOUS_DEADINFO is set, then all ip vecs come from a fixed 4GB buffer
        // printf("%s: Continuous Info: GetNextIPVecBuffer, with size of tb size: %d...\n", 
        //     __FUNCTION__, tb->size);
        newChild->childIPs  = (BlockNode **)GetNextIPVecBuffer(tb->size);
        // initialize as 0, get from IPVecBuffer one by one during mem_callback
        // printf("%s: Continuous Info: initialize childIPs as 0\n", __FUNCTION__);
        // newChild->childIPs = 0;
#else            //no CONTINUOUS_DEADINFO
        printf("Non-Continuous Info: malloc new BlockNode**\n");
        newChild->childIPs = (BlockNode **) malloc( (tb->size) * sizeof(BlockNode **) );
#endif //end CONTINUOUS_DEADINFO

        for(uint32_t i = 0 ; i < tb->size ; i++) {
            newChild->childIPs[i] = newChild;
        }
        // reset nSlots to 0, used to tracking how many write PCs in this TraceBlockNode.
        newChild->nSlots = 0;

        gCurrentContext->childBlocks[currentIp] = newChild;
        gCurrentTraceBlock = newChild;

        // printf("%s: reset gCurrentTraceIpVector pointing to %p, for tb->pc: 0x" TARGET_FMT_lx "\n",
        //     __FUNCTION__, gCurrentTraceBlock->childIPs, gCurrentTraceBlock->address);

        gCurrentTraceIpVector = gCurrentTraceBlock->childIPs;

    }    

}


//  UpdateTraceIPs:
//  lele: now after block executed, we should have traceShadowMap built fully. Then we could use this to update Trace IPs. One BlockNode for a new block.
//  In Deadspy: gBlockShadowMap(gTraceShadowMap) is built during instrumentation. and used here in the instrumentation code.
//  However, in Panda: we built gBlockShadowMap only when there is a mem write detected in mem_callback.
//  So , gBlockShadowMap should be built fully after the exe of the block.
//  So, we need to update BlockNode after block execution.
// Lele: updated: 
// UpdateTraceIPs is splited into two steps:
//  1, allocate all IPs as tb->size at the instrumentBeforeBlockExe
//  2, fill it during mem_callback, at the same time when we fill gBlockShadowMap
//  --> in this way, we could use the &gCurrentTraceIpVector[i] (or &(gCurrentTraceBlock->childIPs[i])) to report as dead context.
//  This way, the gCurrentTraceBlock->childIPs will be filled in the same pace with gBlockShadowMap.
//
//inline void instrumentBeforeBlockExe(ADDRINT currentIp){
// inline void UpdateTraceIPs(CPUState *cpu, TranslationBlock *tb){
// }

/*
 handle_on_call(CPUState *env, target_ulong func);
    --> called on after_block_exe, which means, this block is not the new block, but next block will be a new block by call.

 Refer: callstack_instr.h

*/
void handle_on_call(CPUState *cpu,TranslationBlock *src_tb, target_ulong dst_func){
   
    // printf("Now in %s\n", __FUNCTION__);
    // verify the pc of func by callstack_instr.cpp
    // current pc should be exactly dst_func
    target_ulong pc, cs_base;
    uint32_t flags;
    // This retrieves the pc in an architecture-neutral way
    cpu_get_tb_cpu_state((CPUArchState*)cpu->env_ptr, &pc, &cs_base, &flags);

    if (pc != dst_func){
        printf("%s: ERROR in callstack_instr: given func addr is not the current pc\n", __FUNCTION__);
        exit(-1);
    }
    
     // target_ulong asid_cur = panda_current_asid_proc_struct(cpu);
    //  target_ulong asid_cur = panda_current_asid_proc_struct(cpu);
    //  if (asid_cur != gTargetAsid){
    //         return;
    //  }

    // printf("Now in %s\n", __FUNCTION__);
    bool judge_by_struct;
    target_ulong judge_asid;
    OsiProc *judge_proc;
    bool is_target = is_target_process_running(cpu, &judge_by_struct, &judge_asid, &judge_proc);

    // // // print judge metric, for debug
    // if(judge_by_struct){

    //     printf("%s: judge by name in struct. \n",
    //         __FUNCTION__);
        // printf("\tasid: (cpu->cr3): " TARGET_FMT_lx "\n", judge_asid);
    //     //print full info of proc
    //     print_proc_info(judge_proc);
    // }
    // else{
    //     printf("%s: judge by asid: 0x" TARGET_FMT_lx ", target: 0x" TARGET_FMT_lx "\n",
    //         __FUNCTION__, judge_asid, gTargetAsid);
    // }
    
    if(!is_target){
        // not target process.
        if(gIsTargetBlock){
            printf("%s: WARNING: target detected at before_block_exec but not detected here, might a process switch??\n", __FUNCTION__);
            // exit(-1);
        }else{
            return ;
        }
        return ;
    }else{
        if (! gIsTargetBlock){
            printf("%s: WARNING: target not detected at before_block_exec, but detected here, now check whether it's probably a cr3 overlap\n", __FUNCTION__);

            if (!judge_by_struct) return;

            printf("\tCongratulations! judge by proc struct!\n");    
            printf("\t------- not cr3 overlap, must be a process switch??\n");
            // exit(-1);
            gIsTargetBlock = true;
        }
    }
    
    printf("%s: callstack_instr get a call from block tb->pc: 0x" TARGET_FMT_lx ", to func 0x" TARGET_FMT_lx " \n", __FUNCTION__, src_tb->pc, dst_func);
    
    // 
    // gInitiatedCall = true;

    // Let GoDownCallChain do the work needed to setup pointers for child nodes.
    GoDownCallChain(cpu,dst_func);
}

/*
 handle_on_ret(CPUState *env, target_ulong func);  
    --> called on before_block_exe, which means this block is already in the new block we ret to.

 Refer: callstack_instr.h

*/
void handle_on_ret(CPUState *cpu, TranslationBlock *dst_tb, target_ulong from_func){
    // target_ulong asid_cur = panda_current_asid_proc_struct(cpu);
    //  target_ulong asid_cur = panda_current_asid_proc_struct(env);
    //  if (asid_cur != gTargetAsid){
    //         return;
    //  }

    // printf("Now in %s\n", __FUNCTION__);
    bool judge_by_struct;
    target_ulong judge_asid;
    OsiProc *judge_proc;
    bool is_target = is_target_process_running(cpu, &judge_by_struct, &judge_asid, &judge_proc);

    // // // print judge metric, for debug
    // if(judge_by_struct){

    //     printf("%s: judge by name in struct. \n",
    //         __FUNCTION__);
        // printf("\tasid: (cpu->cr3): " TARGET_FMT_lx "\n", judge_asid);
    //     //print full info of proc
    //     print_proc_info(judge_proc);
    // }
    // else{
    //     printf("%s: judge by asid: 0x" TARGET_FMT_lx ", target: 0x" TARGET_FMT_lx "\n",
    //         __FUNCTION__, judge_asid, gTargetAsid);
    // }
    
    if(!is_target){
       return ;
    }else{
        gIsTargetBlock = true;
        printf("%s: set true to gIsTargetBlock\n", __FUNCTION__);
    }


    printf("%s: callstack_instr detect a ret from func: 0x" TARGET_FMT_lx ", to a target proc's block: tb->pc=0x" TARGET_FMT_lx "\n", __FUNCTION__, from_func, dst_tb->pc);
    
    // 
    // gInitiatedRet = true;

    // detect the ret depth and call GoUpCallChain
    // search up to 10 depth, according to callstack_instr.cpp
    int i = 0;
    int depth = 0;
    target_ulong functions[10];
    int func_cnt = get_functions(functions, 10, cpu);
    for (i=0 ; i < func_cnt; i ++){
        if (from_func == functions[i]){
            break;
        }
    }
    depth = i + 1;

    if (depth > func_cnt){
        printf("%s: ERROR: BUG in callstack_instr: ret has no matching from functions in func stack\n", __FUNCTION__);
        exit(-1);
    }

    printf("%s: go up %d function calls\n", __FUNCTION__, depth);

    GoUpCallChain(cpu, dst_tb, from_func, depth);

}

/**
//PANDA NOTE:
before_block_exec: called before execution of every basic block
    Callback ID: PANDA_CB_BEFORE_BLOCK_EXEC
    Arguments:
        CPUState *env: the current CPU state
        TranslationBlock *tb: the TB we are about to execute
    Return value:
        unused
    Signature:
        int (*before_block_exec)(CPUState *env, TranslationBlock *tb);

//
//Refer  
//  - InstrumentTrace() on every Trace
        static void InstrumentTrace(TRACE trace, void * f){
            INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)InstrumentTraceEntry,IARG_INST_PTR,IARG_END);    
            PopulateIPReverseMapAndAccountTraceInstructions(trace);

        -InstrumentTraceEntry() -> UpdateDataOnFunctionEntry() -> GoDownCallChain(cpu,tb);

        - PopulateIPReverseMapAndAccountTraceInstructions(): 
            - Instruction() -> ManageCallingContext() on every Instruction in 
                - GoUpCallChain
            - build ipShadow before code run. (Allocated here but filled during run. (mem_callback, have size and R/W)
            - get write size and insert statement InstructionContributionOfBBL2Byte to count total write size.(mem_callback, have size and R/W)

**/

int before_block_exec(CPUState *cpu, TranslationBlock *tb) {


    //Lele: if last block initiated a call, then set gInitiatedCall as true. 
    //  Then next block would be inside a new function call.
    //printf("########### Now in %s, pc=0x" TARGET_FMT_lx "\n", __FUNCTION__, tb-> pc);

    //Lele: check asid.
    // target_ulong asid_cur = panda_current_asid_proc_struct(cpu);
    // if (gTraceOne){
    //     if (asid_cur != gTargetAsid){
    //         // printf("%s: ignore ASID 0x" TARGET_FMT_lx "\n", __FUNCTION__, asid_cur);
    //         gIgnoredASIDs.insert(asid_cur);
    //         return 1;
    //     } 
    //     // else{
    //     //     printf("%s: a block for target ASID: 0x" TARGET_FMT_lx "\n", __FUNCTION__, gTargetAsid);
    //     // }
    // }else if (gTraceKernel){
    //     if (asid_cur != 0x0 ){
    //         printf("%s: ignore non-kernel ASID 0x" TARGET_FMT_lx "\n", __FUNCTION__, asid_cur);
    //         gIgnoredASIDs.insert(asid_cur);
    //         return 1;
    //     } else{
    //         printf("\n kernel block\n");
    //     }
    // }else if (gTraceApp){
    //     if (asid_cur == 0x0 ){
    //         printf("%s: ignore kernel ASID 0x" TARGET_FMT_lx "\n", __FUNCTION__, asid_cur);
    //         gIgnoredASIDs.insert(asid_cur);
    //         return 1;
    //     } else{
    //         printf("\nApp block, ASID: 0x" TARGET_FMT_lx "\n", asid_cur);
    //     }
    // }else{
    //     // no filters
    //     printf("%s: a block for ASID: 0x" TARGET_FMT_lx "\n", __FUNCTION__, asid_cur);
    // }


    // printf("Now in %s\n", __FUNCTION__);
    bool judge_by_struct;
    target_ulong judge_asid;
    OsiProc *judge_proc;
    bool is_target = is_target_process_running(cpu, &judge_by_struct, &judge_asid, &judge_proc);

    // // print judge metric, for debug
    // if(judge_by_struct){

    //     printf("%s: judge by name in struct. \n",
    //         __FUNCTION__);
        // printf("\tasid: (cpu->cr3): " TARGET_FMT_lx "\n", judge_asid);
    //     //print full info of proc
    //     print_proc_info(judge_proc);
    // }
    // else{
    //     printf("%s: judge by asid: 0x" TARGET_FMT_lx ", target: 0x" TARGET_FMT_lx "\n",
    //         __FUNCTION__, judge_asid, gTargetAsid);
    // }
    
    if(!is_target){
        return 1;
    }else{
        gIsTargetBlock = true;
        printf("%s: detect a block for the target process: tb->pc: 0x" TARGET_FMT_lx "\n", __FUNCTION__, tb->pc);
    }

    // Refer: ManageCallingContext() -> GoUpCallChain().
    // if(INS_IsProcedureCall(ins) ) {
    // if(gInitiatedCall || gInitiatedINT) {    
    //     GoDownCallChain(cpu, tb); 
    // }else 
    
    // detecting and changing calling context tree is moved to the time when we detect a call/ret.
    // e.g. in after_block_exe, or before_block_exe.

    // if(gInitiatedRet){

    //     // printf("%s:get a new function ret.\n", __FUNCTION__);
    //     gInitiatedRet=false;
    //     GoUpCallChain();
    //     //TODO: check if tb->pc is equal with currentIp
    //     // printf("%s: go up to context: 0x" TARGET_FMT_lx"\n", __FUNCTION__, gCurrentContext->address);
    //     // printf("%s: go up to BasicBlock: 0x" TARGET_FMT_lx"\n", __FUNCTION__, tb->pc);
    // }
    // if(gInitiatedIRET){

    //     // printf("%s:get a new interrupt ret.\n", __FUNCTION__);
    //     gInitiatedIRET=false;
    //     GoUpCallChain();
    //     //TODO: check if tb->pc is equal with currentIp
    //     // printf("%s: go up to context: 0x" TARGET_FMT_lx"\n", __FUNCTION__, gCurrentContext->address);
    //     // printf("%s: go up to BasicBlock: 0x" TARGET_FMT_lx"\n", __FUNCTION__, tb->pc);

    // }
    // if(gInitiatedCall){
    //     //Refer: UpdateDataOnFunctionEntry(cpu, tb); // it will reset   gInitiatedCall      
    //     // normal function call, so unset gInitiatedCall
    //     // printf("%s:get a new function call !\n", __FUNCTION__);
    //     gInitiatedCall = false;

    //     // Let GoDownCallChain do the work needed to setup pointers for child nodes.
    //     GoDownCallChain(cpu,tb);
    //     //TODO: check if tb->pc is equal with currentIp
    //     // printf("%s: go down to context: 0x" TARGET_FMT_lx"\n", __FUNCTION__, gCurrentContext->address);
    //     // printf("%s: go down to BasicBlock: 0x" TARGET_FMT_lx"\n", __FUNCTION__, tb->pc);
        
    // }


    // Refer: InstrumentTrace() TODO
    //InstrumentTraceEntry() -> UpdateDataOnFunctionEntry() -> GoDownCallChain(cpu,tb);

    instrumentBeforeBlockExe(cpu, tb);


    // printf("%s: done. tb->pc=0x" TARGET_FMT_lx "\n", __FUNCTION__, tb-> pc);
    return 1;
}


int after_block_exec(CPUState *cpu, TranslationBlock *tb) {

    // Lele: after block executed. PC would point to the new function if tb has a call instruction at last.
    //
    //printf("########### Now in %s, pc=0x" TARGET_FMT_lx "\n", __FUNCTION__, tb->pc);

    //Lele: check asid.
    // target_ulong asid_cur = panda_current_asid_proc_struct(cpu);
    // if (gTraceOne){
    //     if (asid_cur != gTargetAsid){
    //         // printf("%s: ignore ASID 0x" TARGET_FMT_lx "\n", __FUNCTION__, asid_cur);
    //         gIgnoredASIDs.insert(asid_cur);
    //         return 1;
    //     } 
    //     // else{
    //     //     printf("%s: a block for target ASID: 0x" TARGET_FMT_lx "\n", __FUNCTION__, gTargetAsid);
    //     // }
    // }else if (gTraceKernel){
    //     if (asid_cur != 0x0 ){
    //         printf("%s: ignore non-kernel ASID 0x" TARGET_FMT_lx "\n", __FUNCTION__, asid_cur);
    //         gIgnoredASIDs.insert(asid_cur);
    //         return 1;
    //     } else{
    //         printf("\n kernel block\n");
    //     }
    // }else if (gTraceApp){
    //     if (asid_cur == 0x0 ){
    //         printf("%s: ignore kernel ASID 0x" TARGET_FMT_lx "\n", __FUNCTION__, asid_cur);
    //         gIgnoredASIDs.insert(asid_cur);
    //         return 1;
    //     } else{
    //         printf("\nApp block, ASID: 0x" TARGET_FMT_lx "\n", asid_cur);
    //     }
    // }else{
    //     // no filters
    //     printf("%s: a block for ASID: 0x" TARGET_FMT_lx "\n", __FUNCTION__, asid_cur);
    // }

    // printf("Now in %s\n", __FUNCTION__);
    bool judge_by_struct;
    target_ulong judge_asid;
    OsiProc *judge_proc;
    bool is_target = is_target_process_running(cpu, &judge_by_struct, &judge_asid, &judge_proc);

    // // print judge metric, for debug
    // if(judge_by_struct){

    //     printf("%s: judge by name in struct. \n",
    //         __FUNCTION__);
    //     printf("\tasid: (cpu->cr3): " TARGET_FMT_lx "\n", judge_asid);
    //     //print full info of proc
    //     print_proc_info(judge_proc);
    // }
    // else{
    //     printf("%s: judge by asid: 0x" TARGET_FMT_lx ", target: 0x" TARGET_FMT_lx "\n",
    //         __FUNCTION__, judge_asid, gTargetAsid);
    // }
    
    if(!is_target){
        // not target process.
        if(gIsTargetBlock){
            printf("%s: WARNING: target detected at before_block_exec but not detected here, might a process switch??, tb->pc: 0x " TARGET_FMT_lx "\n", __FUNCTION__, tb->pc);
            // exit(-1);
        }else{
            return 1;
        }
        return 1;
    }else{
        if (! gIsTargetBlock){
            printf("%s: WARNING: target not detected at before_block_exec, but detected here, might a process switch??, or cr3 overlap?? tb->pc: 0x " TARGET_FMT_lx "\n", __FUNCTION__, tb->pc);

            if (!judge_by_struct) return;

            printf("\tCongratulations! judge by proc struct!\n");    
            printf("\t------- not cr3 overlap ! must be a process switch??\n");
        }
    }

    // reset the flag. will be detect and set again in before_block_exe
    if(gIsTargetBlock){
        gIsTargetBlock = false;
    }

    
    //  lele: should update Trace IPs after block executed.
    //  In Deadspy: gBlockShadowMap(gTraceShadowMap) is built during instrumentation. and used here in the instrumentation code.
    //  However, in Panda: we built gBlockShadowMap only when there is a mem write detected in mem_callback.
    //  So , gBlockShadowMap should be built fully after the exe of the block.
    //  So, we need to update BlockNode after block execution.

    // Refer: InstrumentTrace() TODO
    //InstrumentTraceEntry() -> UpdateDataOnFunctionEntry() -> GoDownCallChain(cpu,tb);
    if (gNewBasicBlock){ // only update ChildIPs for one time for each Basic Block.
        gNewBasicBlock=false;
    }
    if (gNewBlockNode){
        gNewBlockNode = false;
    }
    if (! gBlockShadowMapDone[tb->pc]){
        // printf("%s: mark gBlockShadowMap[0x" TARGET_FMT_lx "] as done for this block\n", __FUNCTION__, tb->pc);
        gBlockShadowMapDone[tb->pc]=true;
    }
    // reset slot index, so that in next basic block, we count mem R/W from the begining.
    gCurrentSlot = 0;

    if(block_cache.count(tb->pc) == 0){
        // printf("%s: WARNING: no disasemble cache available for tb->pc: 0x" TARGET_FMT_lx "\n", __FUNCTION__, tb->pc);
        return 1;
    }
    ins_type tb_type = block_cache[tb->pc];
    if (tb_type == INSTR_CALL) {
        printf("%s: call detected, but not set InitiatedCall flag\n", __FUNCTION__);
        // if (gInitiatedCall){
        //     // printf("%s: good, already found by callstack_instr plugin via handle_on_call\n", __FUNCTION__);
        // }else{
        //     // printf("%s: WARNING: call not found by callstack_instr plugin\n", __FUNCTION__);
        //     // gInitiatedCall = true;
        // }
    }else if (tb_type == INSTR_RET) {
        printf("%s: return detected, but not set InitiatedRet flag\n", __FUNCTION__);
        // gInitiatedRet=true;
        // if (gInitiatedRet){
        //     // printf("%s: good, already found by callstack_instr plugin via handle_on_call\n", __FUNCTION__);
        // }else{
        //     // printf("%s: WARNING: ret not found by callstack_instr plugin\n", __FUNCTION__);
        //     gInitiatedRet = true;
        // }

    }else 
    if (tb_type == INSTR_INT) {
        printf("%s: interrupt detected, but not set InitiatedINT flag\n", __FUNCTION__);
        // gInitiatedINT=true;
    }
    else if (tb_type == INSTR_IRET) {
        printf("%s: iret detected, but not set InitiatedIRET flag\n", __FUNCTION__);
        // gInitiatedRet=true;
    }
    return 1;
}


/* int checkNewProc (std::string procName)
    - check whether procName is in gProcs, 
    - if does not exist, add it to gProcs and return its index; 
    - if exists, nothing change and return its index.
*/
int checkNewProc(std::string procName){

    int procIndex;
    std::vector<std::string>::iterator procNameIt =  std::find(gProcs.begin(), gProcs.end(), procName);
    
    if ( procNameIt != gProcs.end() ){
        // an old proc name.
        procIndex = (int) ( procNameIt - gProcs.begin());

    }else{
        // a new proc name.
        // printf("%s: got a new proc: %s\n", 
        //     __FUNCTION__, procName.c_str());
        // store it in gProcs, and the map
        gProcs.push_back(procName);
        procIndex = (int) gProcs.size()-1;
    }

    return procIndex;
}


// only tracking kernel asid, because asidstory pluging skips this
int handle_asid_change(CPUState *cpu, target_ulong old_asid, target_ulong new_asid) {

    // lele: panda BUG: when asid didn't change, we can still reach here...
    if(new_asid == old_asid){
        printf("%s: panda BUG: no asid change here.\n", __FUNCTION__);
        return 0;
    } 

    if (new_asid == 0) {
        // handle_proc_change(cpu, new_asid, );
        printf("%s: TODO: handle kernel binaries here\n", __FUNCTION__);
        return 0;
    }else{
        printf("%s: asid change: old: 0x" TARGET_FMT_lx ", new: 0x" TARGET_FMT_lx "\n", 
            __FUNCTION__, old_asid, new_asid);
        
        return 0;
    }
    // gAsidJustChanged = true; //TODO: might be used to reduce overhead of detecting current process name during mem_callback, or before/after_block_exe
    return 0;
}



/* handle_proc_change

    - this is used to monitor the non-kernel asid changes
    - once a new asid if found, store it's proc name and asid mapping relationship
    - this will change gProcs, gAsidToProcIndex, and gProcFound

Refer pri_dwarf.cpp and asidstory.h 
    - handle asid change in pri_dwarf.
    - using callback from plugin asidstory.
*/
// typedef void (* on_proc_change_t)(CPUState *cpu, target_ulong asid, OsiProc *proc);

void handle_proc_change(CPUState *cpu, target_ulong asid, OsiProc *proc) {
    printf("-----------begin: %s------------\n", __FUNCTION__);
    if (!proc) { return; }
    if (!proc->name) { return; }


    printf("%s: new proc's asid: 0x" TARGET_FMT_lx ", struct_asid: 0x" TARGET_FMT_lx "\n", __FUNCTION__, asid, proc->asid);

    target_ulong asid_struct;
    bool asid_struct_diff = false;

    // printf("a valid: %s\n", __FUNCTION__);
    // check to be safe
    // use the asid by panda_current_asid_proc_struct(cpu). 
    // BUG in Panda: on_proc_change asid can be different with panda_current_asid_proc_struct(cpu)

    // just check to be safe.
    
    // asid_struct should be the same as proc->asid.
    asid_struct = panda_current_asid_proc_struct(cpu);
    if(asid_struct != proc->asid){
        printf("%s: WARNING: BUG in Panda: on_proc_change asid not the struct asid!!\n", __FUNCTION__);
        printf("\t\tstruct asid: 0x" TARGET_FMT_lx "\n", asid_struct);
        printf("\t\ton_proc_change callback asid: 0x" TARGET_FMT_lx "\n", asid);
        exit(-1);
    }

    if (asid_struct != asid){
        asid_struct_diff = true;
        //exit(-1);
    }
    

    printf("%s: proc_change: asid: 0x" TARGET_FMT_lx "(p->asid: 0x" TARGET_FMT_lx 
            "), name: %s, pid: " TARGET_FMT_lu ", ppid: " TARGET_FMT_lu 
            "\n",
        __FUNCTION__, asid, proc->asid, proc->name, proc->pid,proc->ppid);

    printf("\t\t offset: 0x" TARGET_FMT_lx "\n", proc->offset);

    if (proc->pages){
        printf("\t\t page start: 0x" TARGET_FMT_lx " , page len: " TARGET_FMT_lu " \n",   
            proc->pages->start, proc->pages->len);
    }

    // assert(asid == proc->asid);

    std::string curProc(proc->name);
    // store the asid<-> procName mappings
     std::tr1::unordered_map<target_ulong, int>::iterator asidProcIt = gAsidToProcIndex.find(asid);
    
    if (asidProcIt != gAsidToProcIndex.end()){
        // not a new asid. 
        // already a proc name stored. 
        // Now check whether the stored name is the same name as current.
        if (! (gProcs[asidProcIt->second] == curProc)){
            printf("%s: WARNING::(ERROR): gProcs[%d]='%s' for asid 0x" TARGET_FMT_lx ", but curProcName is '%s' for this asid\n" ,
            __FUNCTION__, asidProcIt->second, gProcs[asidProcIt->second].c_str(), asid, proc->name);
            // exit(-1);
            //update if changed
            gProcs[asidProcIt->second] = curProc;
        }
    }else{
        // got a new asid 
        // now check the name. If name already exists, get the index; if not, insert into gProcs and get the new index;
        // use index to store asid -- procName mapping.
        int oldgProcSize = gProcs.size();

        int procIndex=checkNewProc(curProc);

        if (procIndex == oldgProcSize){
            // gProcs is inserted with a new proc
            printf("%s: got a new proc: %s, asid: 0x" TARGET_FMT_lx "\n", 
            __FUNCTION__, curProc.c_str(), asid);
        }
        gAsidToProcIndex[asid] = procIndex;
    }

    // update gAsidToProcIndex regard to asid_struct if different with asid.
    if(asid_struct_diff){

        if (gAsidToProcIndex.count(asid_struct)!=0){
            // not a new asid. 
            // already a proc name stored. 
            // Now check whether the stored name is the same name as current.
            std::string old_procName = gProcs[gAsidToProcIndex[asid_struct]];
            if (! ( old_procName== curProc)){
                printf("%s: WARNING:(ERROR): struct asid proc name diff: gProcs[%d]='%s' for asid 0x" TARGET_FMT_lx ", but curProcName is '%s' for this asid\n" ,
                __FUNCTION__, gAsidToProcIndex[asid_struct], old_procName.c_str(), asid_struct, proc->name);
                // exit(-1);
                //update if changed
                gProcs[gAsidToProcIndex[asid_struct]] = curProc;
            }
        }else{
            // got a new asid 
            // now check the name. If name already exists, get the index; if not, insert into gProcs and get the new index;
            // use index to store asid -- procName mapping.
            int oldgProcSize = gProcs.size();

            int procIndex=checkNewProc(curProc);

            if (procIndex == oldgProcSize){
                // gProcs is inserted with a new proc
                printf("%s: got a new proc: %s, asid(struct): 0x" TARGET_FMT_lx "\n", 
                __FUNCTION__, curProc.c_str(), asid_struct);
            }
            gAsidToProcIndex[asid_struct] = procIndex;
        }
        
     }


    if (curProc == gProcToMonitor){
        // gTargetAsid = asid;
        // printf("%s: reset target asid to 0x" TARGET_FMT_lx ", proc: %s\n", __FUNCTION__, asid, curProc.c_str());
        printf("%s: got asid of target Proc 0x" TARGET_FMT_lx ", proc: %s\n", __FUNCTION__, asid, curProc.c_str());
        if (!gProcFound){
            // this is the monitored process.
            gProcFound = true;
            printf("%s: setting gProcFound to be true\n", __FUNCTION__);
        }
        // keeping the target asid/struct in the same pace.
        gTargetAsid = asid;
        gTargetAsid_struct = asid_struct;
    }else{
        gProcFound = false;
        printf("%s: setting gProcFound to be false\n", __FUNCTION__);
    }



    //get lib/modules and update asid <-> procName mappings as well as asid <-> debugFile mappings
    //
    // Refer: osi_test.c in before_block_exec
    
    // OsiProc *current = get_current_process(cpu);
    // printf("Current process: %s PID:" TARGET_FMT_ld " PPID:" TARGET_FMT_ld "\n", current->name, current->pid, current->ppid);
 
    // OsiModules *ms = get_libraries(cpu, current);
    
    OsiModules *ms = get_libraries(cpu, proc);
    if (ms == NULL) {
        printf("No mapped dynamic libraries.\n");
    }
    else {
        printf("Dynamic libraries list (%d libs):\n", ms->num);
        for (int i = 0; i < ms->num; i++){
            
            // printf("\tasid: 0x" TARGET_FMT_lx "\tsize:" TARGET_FMT_ld "\t%-24s %s\n", ms->module[i].base, ms->module[i].size, ms->module[i].name, ms->module[i].file);

            int oldgProcSize = (int) gProcs.size();
            int procIndex = checkNewProc(std::string(ms->module[i].name));
            if (oldgProcSize == procIndex){
                // a new proc found
                printf("%s: a new dynamic lib found\n\toffset:\t0x" TARGET_FMT_lx "\tbase:\t0x" TARGET_FMT_lx "\tsize:\t0x" TARGET_FMT_lx 
                "\n\tname:\t%s\n\tfile:\t%s\n",
                    __FUNCTION__, 
                    ms->module[i].offset,
                    ms->module[i].base,
                    ms->module[i].size,
                    ms->module[i].name,  
                    ms->module[i].file);
            }
            gAsidToProcIndex[ ms->module[i].base ] = procIndex;
        }
    }

    OsiModules *kms = get_modules(cpu);

    if (kms == NULL) {
        printf("No mapped kernel modules.\n");
    } else {
        printf("Kernel module list (%d modules):\n", kms->num);
        for (int i = 0; i < kms->num; i++){
            // printf("\t0x" TARGET_FMT_lx "\t" TARGET_FMT_ld "\t%-24s %s\n", kms->module[i].base, kms->module[i].size, kms->module[i].name, kms->module[i].file);

            int oldgProcSize = (int) gProcs.size();
            int procIndex = checkNewProc(std::string(kms->module[i].name));
            if (oldgProcSize == procIndex){
                // a new proc found

                printf("%s: a new kernel module found\n\toffset:\t0x" TARGET_FMT_lx "\tbase:\t0x" TARGET_FMT_lx "\tsize:\t0x" TARGET_FMT_lx 
                "\n\tname:\t%s\n\tfile:\t%s\n",
                    __FUNCTION__, 
                    kms->module[i].offset,
                    kms->module[i].base,
                    kms->module[i].size,
                    kms->module[i].name,  
                    kms->module[i].file);
            }
            gAsidToProcIndex[ kms->module[i].base ] = procIndex;
        }
    }

    // exit(-1);

    // clean up 
    // printf("%s: clean up..\n", __FUNCTION__);
    // free_osiproc(current);
    // free_osiproc(proc); // this will cause seg fault after asid_changed, before calling handle_proc_change func..
    free_osimodules(ms);
    free_osimodules(kms); //no clean kms in osi_test.c

    printf("-----------end: %s------------\n\n", __FUNCTION__);
}

void report_deadspy(void * self){
    //lele: ported from deadspy: ExtractDeadMap and Fini
    // 
    //printf("%s: ExtractDeadMap()\n", __FUNCTION__);
    ExtractDeadMap(); //lele: necessary?
    //
    printf("%s: Fini()\n", __FUNCTION__);
    Fini();
}

// void clear_insn(){
//     std::tr1::unordered_map<target_ulong, cs_insn *>::iterator insnIt;
//     for (insnIt = tb_insns.begin(); insnIt != tb_insns.end(); insnIt ++ ){
//         int count = tb_insns_count[insnIt -> first];
//         cs_insn * insn = insnIt->second;
//         cs_free(insn, count);
//     }

// }

// TODO void clear gBlockShadowMap and gBlockShadowIPtoSlots
// TODO void clear
void uninit_plugin(void *self) {

    printf("%s: report deadspy\n", __FUNCTION__);
    report_deadspy(self);
    // clear_insn();

    printAllProcsFound();

    // std::map<prog_point,match_strings>::iterator it;

    // for(it = matches.begin(); it != matches.end(); it++) {
    //     // Print prog point

    //     // Most recent callers are returned first, so print them
    //     // out in reverse order
    //     CallStack &f = matchstacks[it->first];
    //     for (int i = f.n-1; i >= 0; i--) {
    //         fprintf(gTraceFile, TARGET_FMT_lx " ", f.callers[i]);
    //     }
    //     fprintf(gTraceFile, TARGET_FMT_lx " ", f.pc);
    //     fprintf(gTraceFile, TARGET_FMT_lx " ", f.asid);

    //     // Print strings that matched and how many times
    //     for(int i = 0; i < num_strings; i++)
    //         fprintf(gTraceFile, " %d", it->second.val[i]);
    //     fprintf(gTraceFile, "\n");
    // }

    // printf("\nlog writtent to %s\n", trace_file_kernel);
    // printf("\nlog writtent to %s\n", trace_file_user);

    // fclose(gTraceFile);
    // fclose(gTraceFile_user);
}



// Initialized the needed data structures before launching the target program
// void InitDeadSpy(int argc, char *argv[]){
void init_deadspy(const char * prefix){
 //Lele: from deadspy continuous deadinfo
    
#if defined(CONTINUOUS_DEADINFO)
    // prealloc 4GB (or 32GB) ip vec
    // IMPROVEME ... actually this can be as high as 24 GB since lower 3 bits are always zero for pointers
    gPreAllocatedContextBuffer = (void **) mmap(0, PRE_ALLOCATED_BUFFER_SIZE, PROT_WRITE
                                                | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    // start from index 1 so that we can use 0 as empty key for the google hash table
    gCurPreAllocatedContextBufferIndex = 1;
    //DeadMap.set_empty_key(0);
#else //no defined(CONTINUOUS_DEADINFO)        
    // FIX ME FIX ME ... '3092462950186394283' may not be the right one to use, but dont know what to use :(.
    // 3092462950186394283 is derived as the hash of two '0' contexts which is impossible.
    DeadMap.set_empty_key(3092462950186394283);
#endif //end defined(CONTINUOUS_DEADINFO)        
    // 0 can never be a ADDRINT key of a trace        
#ifdef IP_AND_CCT
    //gBlockShadowMap.set_empty_key(0);
#endif //end   IP_AND_CCT   
    
    // Create output file 
    
    //lele: step3: open log file handler, and print first line
    sprintf(trace_file_kernel, "%s_deadwrite_kernel.txt", prefix);
    sprintf(trace_file_user, "%s_deadwrite_user.txt", prefix);
    gTraceFile = fopen(trace_file_kernel, "w");
    gTraceFile_user = fopen(trace_file_user, "w");
    if(!gTraceFile) {
        printf("Couldn't write report for kernel:\n");
        perror("fopen");
        return false;
    }
    if(!gTraceFile_user) {
        printf("Couldn't write report for user:\n");
        perror("fopen");
        return false;
    }
    // Print rw/ addr callers, pc , asid
    fprintf(gTraceFile, "R/W\taddr\t\t[callers]\tpc\tasid\n");
    fprintf(gTraceFile_user, "R/W\taddr\t\t[callers]\tpc\tasid\n");

    
#ifdef GATHER_STATS
    std::string statFileName(trace_file_kernel);
    statFileName += ".stats";
    statsFile = fopen(statFileName.c_str() , "w");
    fprintf(statsFile,"\n");
    // for(int i = 0 ; i < argc; i++){
    //     fprintf(statsFile,"%s ",argv[i]);
    // }
    fprintf(statsFile,"\n");
#endif //end   GATHER_STATS      
    
    // Initialize the context tree
    InitContextTree();        
}


bool init_plugin(void *self) {

    panda_arg_list *args;

    panda_cb pcb;


    //lele: step 1, parse args

    args = panda_get_args("trace_deadwrite");


    target_ulong asid = panda_parse_ulong_opt(args, "asid", 0 , "a single asid to search for");

    if (asid == 0){
        // no ASID parameter given, set the default behavior as following:
        printf("%s: asid given as 0, or not given , or invalid, now use default value 0\n",__FUNCTION__);
        //gTargetAsid = 0x0; 
        //gTraceKernel=true;
        //gTraceApp=true;
        // gTraceOne=true;
        gTargetAsid = 0;
        gTargetAsid_struct = 0;
        //gTargetAsid = 0x000000001fb14000;
        //gTargetAsid = 0x0;
    }else{
        // set target asid as input asid.
        // gTraceOne=true;
        gTargetAsid = asid;
        gTargetAsid_struct = asid;
    }
    printf("%s: target asid/asid_struct: 0x" TARGET_FMT_lx "\n", __FUNCTION__, gTargetAsid);

    const char *proc_to_monitor = panda_parse_string_req(args, "proc", "name of process to follow with debug info");

    gProcToMonitor = std::string(proc_to_monitor);
    printf("%s: process to monitor: %s\n", __FUNCTION__, proc_to_monitor);

    const char *debug_list = panda_parse_string_opt(args, "debug_paths", "debug_paths.txt", "the file name that stores all the possible debug symbol directories, default as debug_paths.txt");

    // read the paths from the file
    if (strlen(debug_list) > 0) {

        std::ifstream debug_file_names(debug_list);
        if (!debug_file_names) {
            printf("Couldn't open %s; no strings to search for. Exiting.\n", debug_list);
            return false;
        }

        std::string line;
        while(std::getline(debug_file_names, line)) {
            printf("%s: add %s to Debug Paths\n", __FUNCTION__, line.c_str());
            gDebugFiles.push_back(line);
        }

    }else{
        printf("%s: WARNING: no debug info path found\n", __FUNCTION__);
    }

    //lele: step 2: sys int: set callstack plugins, enable precise pc, memcb, and set callback functions.


    panda_require("callstack_instr");
    if(!init_callstack_instr_api())
    {
        printf("%s: cannot init callstack_instr\n", __FUNCTION__);
        return false;
    } 

    panda_require("osi");
    assert(init_osi_api());
    panda_require("osi_linux");
    assert(init_osi_linux_api());
    
    panda_require("asidstory");

    
    // assert(init_callstack_instr_api());
    // assert(init_asidstory_api());
    // assert(init_pri_api());


//#################################################
// ADD support of pri_dwarf. get Line Number and Source File Name by PC.
    // only support i386
    // Refer: pri_simple, pri_dwarf
// #if defined(TARGET_I386) && !defined(TARGET_X86_64)
//     args = panda_get_args("pri_taint");
//     panda_require("pri");
//     assert(init_pri_api());
//     panda_require("pri_dwarf");
//     assert(init_pri_dwarf_api());

//     // PPP_REG_CB("pri", on_before_line_change, on_line_change);
//     //PPP_REG_CB("pri", on_fn_start, on_fn_start);
//     // {
//     //     panda_cb pcb;
//     //     pcb.virt_mem_before_write = virt_mem_write;
//     //     panda_register_callback(self,PANDA_CB_VIRT_MEM_BEFORE_WRITE,pcb);
//     //     pcb.virt_mem_after_read = virt_mem_read;
//     //     panda_register_callback(self,PANDA_CB_VIRT_MEM_AFTER_READ,pcb);
//     // }
// #endif
// END support of pri_dwarf.
//######################################################
    

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    panda_do_flush_tb();
    printf("do_flush_tb enabled\n");
    //tb chaining disable
    panda_disable_tb_chaining();
    printf("panda basic block chaining disabled\n");



    // use asidstory to find out the asid's of the ProcToMonitor.

    PPP_REG_CB("asidstory", on_proc_change, handle_proc_change);
    PPP_REG_CB("callstack_instr", on_call2, handle_on_call);
    PPP_REG_CB("callstack_instr", on_ret2, handle_on_ret);


    pcb.asid_changed = handle_asid_change;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    pcb.virt_mem_before_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);

    /*
    virt_mem_after_write: called after memory is written
        Arguments:
            CPUState *env: the current CPU state
            target_ulong pc: the guest PC doing the write
            target_ulong addr: the (virtual) address being written
            target_ulong size: the size of the write
            void *buf: pointer to the data that was written
        Return value:
            unused
        Notes:
            You must call panda_enable_memcb() to turn on memory callbacks before this callback will take effect.
        Signature:
            int (*virt_mem_after_write)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
    */

    // pcb.virt_mem_after_write = mem_write_callback;
    // panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);
    
    /*
    virt_mem_after_read: called after memory is read
        Arguments:
            CPUState *env: the current CPU state
            target_ulong pc: the guest PC doing the read
            target_ulong addr: the (virtual) address being read
            target_ulong size: the size of the read
            void *buf: pointer to data just read
        Return value:
            unused
        Notes:
            You must call panda_enable_memcb() to turn on memory callbacks before this callback will take effect.
        Signature:
            int (*virt_mem_after_read)(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
    */
    pcb.virt_mem_after_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);


    /*
    after_block_translate: called after the translation of each basic block
        Arguments:
            CPUState *env: the current CPU state
            TranslationBlock *tb: the TB we just translated
        Return value:
            unused
        Signature:
            int (*after_block_translate)(CPUState *env, TranslationBlock *tb);
    */
    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);

    /*
    before_block_exec: called before execution of every basic block
        Arguments:
            CPUState *env: the current CPU state
            TranslationBlock *tb: the TB we are about to execute
        Return value:
            unused
        Signature:
            int (*before_block_exec)(CPUState *env, TranslationBlock *tb);
    */
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    /*after_block_exec: called after execution of every basic block

    Callback ID: PANDA_CB_AFTER_BLOCK_EXEC
    Arguments:
        CPUState *env: the current CPU state
        TranslationBlock *tb: the TB we just executed
    Return value:
        unused
    Signature::
        int (*after_block_exec)(CPUState *env, TranslationBlock *tb);
    */
    pcb.after_block_exec = after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);


    //step 3: deadspy init.
    // 
    //lele: init_deadspy: open log file handlers, print first lines, create cct tree, etc.
    const char *prefix="trace_deadwrite_test";
    init_deadspy(prefix);


    return true;
}

