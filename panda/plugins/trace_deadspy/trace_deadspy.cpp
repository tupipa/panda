/*
 * plugin: trace_deadspy, based on trace_instrblock
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


#include <stdio.h>
#include <stdlib.h>
//#include "pin.H"
//#include <map>
#include <ext/hash_map>
#include <list>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <locale>
#include <unistd.h>
#include <sys/syscall.h>
#include <iostream>
#include <assert.h>
#include <sys/mman.h>
#include <exception>
#include <sys/time.h>
#include <signal.h>
//#include <string.h>
#include <setjmp.h>
#include <sstream>
// Need GOOGLE sparse hash tables
#include <google/sparse_hash_map>
#include <google/dense_hash_map>
using google::sparse_hash_map;      // namespace where class lives by default
using google::dense_hash_map;      // namespace where class lives by default
using namespace __gnu_cxx;
using namespace std;


//typedef std::map<std::string,int> instr_hist;

#define MAX_FILE_PATH   (200)


#define WINDOW_SIZE 100

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}


csh handle;
cs_insn *insn;
bool init_capstone_done = false;
target_ulong asid;
int sample_rate = 100;
FILE *log_file;

#ifdef GATHER_STATS
FILE *statsFile;
#endif //end GATHER_STATS



#ifdef IP_AND_CCT
sparse_hash_map<ADDRINT, TraceNode *>::iterator gTraceIter;
//dense_hash_map<ADDRINT, void *> gTraceShadowMap;
hash_map<ADDRINT, void *> gTraceShadowMap;
TraceNode * gCurrentTrace;

bool gInitiatedCall = true;
TraceNode ** gCurrentIpVector;

uint32_t gContextTreeIndex;

struct ContextTree{
    ContextNode * rootContext;
    ContextNode * currentContext;
};
vector<ContextTree> gContextTreeVector;

VOID GoDownCallChain(ADDRINT);
VOID UpdateDataOnFunctionEntry(ADDRINT currentIp);
VOID Instruction(INS ins, uint32_t slot);

//#ifndef MULTI_THREADED
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
// //#else  // no MULTI_THREADED

// // The following functions accummulates the number of bytes written in this basic block categorized by the write size. 

// inline VOID InstructionContributionOfBBL1Byte(uint32_t count){    
//     gContextTreeVector[(uint32_t)PIN_ThreadId()].mt1ByteWriteInstrCount  +=  count;
// }
// inline VOID InstructionContributionOfBBL2Byte(uint32_t count){
//     gContextTreeVector[(uint32_t)PIN_ThreadId()].mt2ByteWriteInstrCount += count;
// }
// inline VOID InstructionContributionOfBBL4Byte(uint32_t count){
//     gContextTreeVector[(uint32_t)PIN_ThreadId()].mt4ByteWriteInstrCount += count;
// }
// inline VOID InstructionContributionOfBBL8Byte(uint32_t count){
//     gContextTreeVector[(uint32_t)PIN_ThreadId()].mt8ByteWriteInstrCount += count;
// }
// inline VOID InstructionContributionOfBBL10Byte(uint32_t count){
//     gContextTreeVector[(uint32_t)PIN_ThreadId()].mt10ByteWriteInstrCount += count;
// }
// inline VOID InstructionContributionOfBBL16Byte(uint32_t count){
//     gContextTreeVector[(uint32_t)PIN_ThreadId()].mt16ByteWriteInstrCount +=  count;
// }
// inline VOID InstructionContributionOfBBLLargeByte(uint32_t count){
//     gContextTreeVector[(uint32_t)PIN_ThreadId()].mtLargeByteWriteInstrCount += count;
// }

// #endif // end MULTI_THREADED


// Called each time a new trace is JITed.
// Given a trace this function adds instruction to each instruction in the trace. 
// It also adds the trace to a hash table "gTraceShadowMap" to maintain the reverse mapping from a write instruction's position in CCT back to its IP.

inline VOID PopulateIPReverseMapAndAccountTraceInstructions(TRACE trace){
    
    uint32_t traceSize = TRACE_Size(trace);    
    ADDRINT * ipShadow = (ADDRINT * )malloc( (1 + traceSize) * sizeof(ADDRINT)); // +1 to hold the number of slots as a metadata
    ADDRINT  traceAddr = TRACE_Address(trace);
    uint32_t slot = 0;
    
    
    // give space to account for nSlots which we record later once we know nWrites
    ADDRINT * pNumWrites = ipShadow;
    ipShadow ++;
    
    gTraceShadowMap[traceAddr] = ipShadow ;
    for( BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl) ){
    	uint32_t inst1ByteSize = 0;
        uint32_t inst2ByteSize = 0;
    	uint32_t inst4ByteSize = 0;
    	uint32_t inst8ByteSize = 0;
    	uint32_t inst10ByteSize = 0;
    	uint32_t inst16ByteSize = 0;
    	uint32_t instLargeByteSize  = 0;
        
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
            // instrument instruction
            Instruction(ins,slot);		
            if(INS_IsMemoryWrite(ins)){
                // put next slot in corresponding ins start location;
                ipShadow[slot] = INS_Address(ins);
                slot++;
                
                // get instruction info in trace                
                USIZE writeSize = INS_MemoryWriteSize(ins);
                switch(writeSize){
                    case 1: inst1ByteSize++;
                        break;
                    case 2:inst2ByteSize++;
                        break;
                    case 4:inst4ByteSize++;
                        break;
                    case 8:inst8ByteSize++;
                        break;
                    case 10:inst10ByteSize++;
                        break;
                    case 16:inst16ByteSize++;
                        break;
                    default:
                        instLargeByteSize += writeSize;
                        //assert(0 && "NOT IMPLEMENTED ... SHOULD NOT SEE large writes in trace");
                }
            }
        }
        
        
        // Insert a call to corresponding count routines before every bbl, passing the number of instructions
        
        // Increment Inst count by trace
        if (inst1ByteSize)
            BBL_InsertCall(bbl,IPOINT_BEFORE, (AFUNPTR) InstructionContributionOfBBL1Byte, IARG_UINT32, inst1ByteSize, IARG_END);     
        if (inst2ByteSize)
            BBL_InsertCall(bbl,IPOINT_BEFORE, (AFUNPTR) InstructionContributionOfBBL2Byte, IARG_UINT32, inst2ByteSize, IARG_END);     
        if (inst4ByteSize)
            BBL_InsertCall(bbl,IPOINT_BEFORE, (AFUNPTR) InstructionContributionOfBBL4Byte, IARG_UINT32, inst4ByteSize, IARG_END);     
        if (inst8ByteSize)
            BBL_InsertCall(bbl,IPOINT_BEFORE, (AFUNPTR) InstructionContributionOfBBL8Byte, IARG_UINT32, inst8ByteSize, IARG_END);     
        if (inst10ByteSize)
            BBL_InsertCall(bbl,IPOINT_BEFORE, (AFUNPTR) InstructionContributionOfBBL10Byte, IARG_UINT32, inst10ByteSize, IARG_END);     
        if (inst16ByteSize)
            BBL_InsertCall(bbl,IPOINT_BEFORE, (AFUNPTR) InstructionContributionOfBBL16Byte, IARG_UINT32, inst16ByteSize, IARG_END);     
        if (instLargeByteSize)
            BBL_InsertCall(bbl,IPOINT_BEFORE, (AFUNPTR) InstructionContributionOfBBLLargeByte, IARG_UINT32, instLargeByteSize, IARG_END);     
        
    }
    
    // Record the number of child write IPs i.e., number of "slots"
    *pNumWrites = slot;
    
}



// #ifdef CONTINUOUS_DEADINFO
// // TODO - support MT. I dont think this needs to be thread safe since PIN guarantees that.
// inline void ** GetNextIPVecBuffer(uint32_t size){
//     void ** ret = gPreAllocatedContextBuffer + gCurPreAllocatedContextBufferIndex;
//     gCurPreAllocatedContextBufferIndex += size;
//     assert( gCurPreAllocatedContextBufferIndex  < (PRE_ALLOCATED_BUFFER_SIZE)/(sizeof(void **)));
//     return ret;
// }
// #endif //end CONTINUOUS_DEADINFO



// Does necessary work on a trace entry (called during runtime)
// 1. If landed here due to function call, then go down in CCT.
// 2. Look up the current trace under the CCT node creating new if if needed.
// 3. Update global iterators and curXXXX pointers.

inline void InstrumentTraceEntry(ADDRINT currentIp){
    
    // if landed due to function call, create a child context node
    
    if(gInitiatedCall){
        UpdateDataOnFunctionEntry(currentIp); // it will reset   gInitiatedCall      
    }
    
    // Check if a trace node with currentIp already exists under this context node
    if( (gTraceIter = (gCurrentContext->childTraces).find(currentIp)) != gCurrentContext->childTraces.end()) {
        gCurrentTrace = gTraceIter->second;
        gCurrentIpVector = gCurrentTrace->childIPs;
    } else {
        // Create new trace node and insert under the context node.
        
        TraceNode * newChild = new TraceNode();
        newChild->parent = gCurrentContext;
        newChild->address = currentIp;
    	uint64_t * currentTraceShadowIP = (uint64_t *) gTraceShadowMap[currentIp];
        uint64_t recordedSlots = currentTraceShadowIP[-1]; // present one behind
        if(recordedSlots){
#ifdef CONTINUOUS_DEADINFO
            // if CONTINUOUS_DEADINFO is set, then all ip vecs come from a fixed 4GB buffer
            newChild->childIPs  = (TraceNode **)GetNextIPVecBuffer(recordedSlots);
#else            //no CONTINUOUS_DEADINFO
            newChild->childIPs = (TraceNode **) malloc( (recordedSlots) * sizeof(TraceNode **) );
#endif //end CONTINUOUS_DEADINFO
            newChild->nSlots = recordedSlots;
            //cerr<<"\n***:"<<recordedSlots; 
            for(uint32_t i = 0 ; i < recordedSlots ; i++) {
                newChild->childIPs[i] = newChild;
            }
        } else {
            newChild->nSlots = 0;
            newChild->childIPs = 0;            
        }          
        
        gCurrentContext->childTraces[currentIp] = newChild;
        gCurrentTrace = newChild;
        gCurrentIpVector = gCurrentTrace->childIPs;
    }    
}

// Instrument a trace, take the first instruction in the first BBL and insert the analysis function before that
static void InstrumentTrace(TRACE trace, void * f){
    BBL bbl = TRACE_BblHead(trace);
    INS ins = BBL_InsHead(bbl);
    INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)InstrumentTraceEntry,IARG_INST_PTR,IARG_END);    
    PopulateIPReverseMapAndAccountTraceInstructions(trace);
}


static void OnSig(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT *ctxtFrom,
                  CONTEXT *ctxtTo, INT32 sig, VOID *v) {
#if 0    
    switch (reason) {
        case CONTEXT_CHANGE_REASON_FATALSIGNAL:
            cerr<<"\n FATAL SIGNAL";
        case CONTEXT_CHANGE_REASON_SIGNAL:
            
            cerr<<"\n SIGNAL";
            
            gContextTreeVector[gContextTreeIndex].currentContext = gCurrentContext;
            gContextTreeIndex++;
            gCurrentContext = gContextTreeVector[gContextTreeIndex].currentContext;
            gRootContext = gContextTreeVector[gContextTreeIndex].rootContext;
            // rest will be set as we enter the signal callee
            gInitiatedCall = true; // so that we create a child node        
            
            break;
            
        case CONTEXT_CHANGE_REASON_SIGRETURN:
        {
            
            cerr<<"\n SIG RET";
            gContextTreeIndex--;
            gCurrentContext = gContextTreeVector[gContextTreeIndex].currentContext;
            gRootContext = gContextTreeVector[gContextTreeIndex].rootContext;
            gCurrentTraceIP = gCurrentContext->address;
            gCurrentTraceShadowIP = gTraceShadowMap[gCurrentTraceIP];
            break;
        }
        default: assert(0 && "\n BAD CONTEXT SWITCH");
    }
#endif    
}


// Analysis routine called on entering a function (found in symbol table only)
inline VOID UpdateDataOnFunctionEntry(ADDRINT currentIp){
    
    // if I enter here due to a tail-call, then we will make it a child under the parent context node
    if (!gInitiatedCall){
        gCurrentContext = gCurrentContext->parent;
    } else {
        // normal function call, so unset gInitiatedCall
        gInitiatedCall = false;
    }
    
    // Let GoDownCallChain do the work needed to setup pointers for child nodes.
    GoDownCallChain(currentIp);
    
}

// Analysis routine called on making a function call
inline VOID SetCallInitFlag(){
    gInitiatedCall = true;
}


// Instrumentation for the function entry (found in symbol table only).
// Get the first instruction of the first BBL and insert call to the analysis routine before it.

inline VOID InstrumentFunctionEntry(RTN rtn, void *f){
    RTN_Open(rtn);
    INS ins = RTN_InsHeadOnly(rtn);
    INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)UpdateDataOnFunctionEntry, IARG_INST_PTR,IARG_END);
    RTN_Close(rtn);    
}
#endif //end IP_AND_CCT




// Is called for every instruction and instruments reads and writes
#ifdef IP_AND_CCT
VOID Instruction(INS ins, uint32_t slot) {
#else
    VOID Instruction(INS ins, VOID * v) {
#endif            
        
        // Note: predicated instructions are correctly handled as given in PIN's sample example pinatrace.cpp
        
        /* Comment taken from PIN sample : 
         Instruments memory accesses using a predicated call, i.e.
         the instrumentation is called iff the instruction will actually be executed.
         
         The IA-64 architecture has explicitly predicated instructions.
         On the IA-32 and Intel(R) 64 architectures conditional moves and REP
         prefixed instructions appear as predicated instructions in Pin. */
        
        
        // How may memory operations?
        UINT32 memOperands = INS_MemoryOperandCount(ins);
        
        // If it is a memory write then count the number of bytes written 
#ifndef IP_AND_CCT  
        // IP_AND_CCT uses traces to detect instructions & their write size hence no instruction level counting is needed
        if(INS_IsMemoryWrite(ins)){
            USIZE writeSize = INS_MemoryWriteSize(ins);
            switch(writeSize){
                case 1:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Do1ByteCount, IARG_END);
                    break;
                case 2:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Do2ByteCount, IARG_END);
                    break;
                case 4:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Do4ByteCount, IARG_END);
                    break;
                case 8:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Do8ByteCount, IARG_END);
                    break;
                case 10:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Do10ByteCount, IARG_END);
                    break;
                case 16:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Do16ByteCount, IARG_END);
                    break;
                default:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) DoLargeByteCount,IARG_MEMORYWRITE_SIZE, IARG_END);
            }                
        }
#endif //end  ifndef IP_AND_CCT         
        
        
        // If it is a call/ret instruction, we need to adjust the CCT.
        ManageCallingContext(ins);
        
        
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
        
        // Iterate over each memory operand of the instruction and add Analysis routine to check for dead writes.
        // We correctly handle instructions that do both read and write.
        
        for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
            UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
            switch(refSize){
                case 1:{
                    if (INS_MemoryOperandIsRead(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record1ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);                        
                        
                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                 (AFUNPTR) Record1ByteMemWrite,
#ifdef IP_AND_CCT
                                                 IARG_UINT32, slot,
#endif
                                                 IARG_MEMORYOP_EA,
                                                 memOp, IARG_END);
                        
                    }
                }
                    break;
                    
                case 2:{
                    if (INS_MemoryOperandIsRead(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record2ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
                        
                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)) {   
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                 (AFUNPTR) Record2ByteMemWrite, 
#ifdef IP_AND_CCT
                                                 IARG_UINT32, slot,
#endif
                                                 IARG_MEMORYOP_EA,
                                                 memOp, IARG_END);
                        
                    }
                }
                    break;
                    
                case 4:{
                    if (INS_MemoryOperandIsRead(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record4ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
                        
                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                 (AFUNPTR) Record4ByteMemWrite,
#ifdef IP_AND_CCT
                                                 IARG_UINT32, slot,
#endif
                                                 IARG_MEMORYOP_EA,
                                                 memOp, IARG_END);
                        
                    }
                }
                    break;
                    
                case 8:{
                    if (INS_MemoryOperandIsRead(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record8ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
                        
                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                 (AFUNPTR) Record8ByteMemWrite,
#ifdef IP_AND_CCT
                                                 IARG_UINT32, slot,
#endif
                                                 IARG_MEMORYOP_EA,
                                                 memOp, IARG_END);
                        
                    }
                }
                    break;
                    
                case 10:{
                    if (INS_MemoryOperandIsRead(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record10ByteMemRead, IARG_MEMORYOP_EA,memOp, IARG_END);
                        
                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                 (AFUNPTR) Record10ByteMemWrite,
#ifdef IP_AND_CCT
                                                 IARG_UINT32, slot,
#endif
                                                 IARG_MEMORYOP_EA,
                                                 memOp, IARG_END);
                        
                    }
                }
                    break;
                    
                case 16:{ // SORRY! XMM regs use 16 bits :((
                    if (INS_MemoryOperandIsRead(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,(AFUNPTR) Record16ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
                        
                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                 (AFUNPTR) Record16ByteMemWrite,
#ifdef IP_AND_CCT
                                                 IARG_UINT32, slot,
#endif
                                                 IARG_MEMORYOP_EA,memOp, IARG_END);
                        
                    }
                }
                    break;
                    
                default: {
                    // seeing some stupid 10, 16, 512 (fxsave)byte operations. Suspecting REP-instructions.
                    if (INS_MemoryOperandIsRead(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,(AFUNPTR) RecordLargeMemRead, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_END);
                        
                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                 (AFUNPTR) RecordLargeMemWrite,
#ifdef IP_AND_CCT
                                                 IARG_UINT32, slot,
#endif
                                                 IARG_MEMORYOP_EA,memOp, IARG_MEMORYWRITE_SIZE, IARG_END);
                        
                    }
                }
                    break;
                    //assert( 0 && "BAD refSize");
                    
            }
        }
        
#ifdef MULTI_THREADED
        // Support for MT
        // release the lock if we had taken it
        if (lockNeeded) {            
            INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) ReleaseLock, IARG_END);
        }
#endif //end MULTI_THREADED
        
    }

    
    INT32 Usage() {
        PIN_ERROR("DeadSPy is a PinTool which tracks each memory access and reports dead writes.\n" + KNOB_BASE::StringKnobSummary() + "\n");        
        return -1;        
    }
    
    // When we make System calls we need to update the shadow regions with the effect of the system call
    // TODO: handle other system calls. Currently only SYS_write is handled.
    
    VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std,
                      VOID *v) {
        ADDRINT number = PIN_GetSyscallNumber(ctxt, std);
        switch (number) {
            case SYS_write: {
                char * bufStart = (char *) PIN_GetSyscallArgument(ctxt, std, 1);
                char * bufEnd = bufStart
                + (size_t) PIN_GetSyscallArgument(ctxt, std, 2);
#ifdef DEBUG
                printf("\n WRITE %p - %p\n",bufStart, bufEnd);
#endif //end DEBUG                
                while (bufStart < bufEnd)
                    Record1ByteMemRead( bufStart++);
            }
                break;
            default: 
                break;//NOP     
        }
        
    }
    

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
#else // no IP_AND_CCT
    gCurrentContext = gRootContext = new ContextNode();
    gRootContext->parent = 0;
    gRootContext->address = 0;
    
#endif // end IP_AND_CCT    
    
    // Init the  segv handler that may happen (due to PIN bug) when unwinding the stack during the printing    
    memset (&gSigAct, 0, sizeof(struct sigaction));
    gSigAct.sa_handler = SegvHandler;
    gSigAct.sa_flags = SA_NOMASK ;
    
}

// #else // MULTI_THREADED

// // Initialized the fields of the root node of all context trees
// VOID InitContextTree(){
//     // Multi threaded coded have a ContextTree per thread, my code assumes a max of 10 threads, for other values redefine CONTEXT_TREE_VECTOR_SIZE
//     // We intialize all fields of the context tree which includes per thread stats
    
    
//     // MAX 10 context trees
//     gContextTreeVector.reserve(CONTEXT_TREE_VECTOR_SIZE);
//     for(uint8_t i = 0 ; i < CONTEXT_TREE_VECTOR_SIZE ; i++){
//         ContextNode * rootNode = new ContextNode();
//         rootNode->address = 0;
//         rootNode->parent = 0;        
//         gContextTreeVector[i].rootContext = rootNode;
//         gContextTreeVector[i].currentContext = rootNode;
//         gContextTreeVector[i].mt1ByteWriteInstrCount = 0;
//         gContextTreeVector[i].mt2ByteWriteInstrCount = 0;
//         gContextTreeVector[i].mt4ByteWriteInstrCount = 0;
//         gContextTreeVector[i].mt8ByteWriteInstrCount = 0;
//         gContextTreeVector[i].mt10ByteWriteInstrCount = 0;
//         gContextTreeVector[i].mt16ByteWriteInstrCount = 0;
//         gContextTreeVector[i].mtLargeByteWriteInstrCount = 0;
//         gContextTreeVector[i].mtLargeByteWriteByteCount = 0;
//     }
    
//     // Init the  segv handler that may happen (due to PIN bug) when unwinding the stack during the printing    
    
//     memset (&gSigAct, 0, sizeof(struct sigaction));
//     gSigAct.sa_handler = SegvHandler;
//     gSigAct.sa_flags = SA_NOMASK ;
    
// }

#endif // end MULTI_THREADED


// Initialized the needed data structures before launching the target program

void InitDeadSpy(){
    
    printf("in init_plugin..\n");
    panda_arg_list *args = panda_get_args("deadspy");
    const char *name_pre = panda_parse_string(args, "name", "deadspy_out");
    asid = panda_parse_ulong(args, "asid", 0);
    //sample_rate = panda_parse_uint32(args, "sample_rate", 1000);

       
        
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
        //gTraceShadowMap.set_empty_key(0);
#endif //end   IP_AND_CCT   
        
        
        
        // Create output file 
        
        char name[MAX_FILE_PATH];
        
        //char fname[260];
        sprintf(name, "%s_", name_pre);

        char * envPath = getenv("DEADSPY_OUTPUT_FILE");
        if(envPath){
            // assumes max of MAX_FILE_PATH
            strcpy(name, envPath);
        } 
        
        gethostname(name + strlen(name), MAX_FILE_PATH - strlen(name));
        pid_t pid = getpid();
        
        sprintf(name + strlen(name),"%d.trace",pid);

        cerr << "\n Creating dead info file at:" << name << "\n";
        
        log_file = fopen(name, "w");


        // print the arguments passed

        fprintf (log_file, "asid: 0x" TARGET_FMT_lx "\n", asid);
        //fprintf (log_file, "address:\tmnemonic\top_str\n");

        // fprintf(log_file,"\n");
        // for(int i = 0 ; i < argc; i++){
        //     fprintf(log_file,"%s ",argv[i]);
        // }
        // fprintf(log_file,"\n");
        
#ifdef GATHER_STATS
        string statFileName(name);
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
//    int main(int argc, char *argv[]) {
        
        // Initialize PIN
       // if (PIN_Init(argc, argv))
         //   return Usage();
        
        // Initialize Symbols, we need them to report functions and lines
        //PIN_InitSymbols();
        
        // Intialize DeadSpy
        InitDeadSpy(argc, argv);
        
        
#ifdef IP_AND_CCT
        // Register for context change in case of signals .. Actually this is never used. // Todo: - fix me
        PIN_AddContextChangeFunction(OnSig, 0);
        
        // Instrument the entry to each "known" function. Some functions may not be known
        RTN_AddInstrumentFunction(InstrumentFunctionEntry,0);
        
        // Since some functions may not be known, instrument every "trace"
        TRACE_AddInstrumentFunction(InstrumentTrace,0);
// #else //no IP_AND_CCT        
//         //IP_AND_CCT case calls via TRACE_AddInstrumentFunction
        
//         // When line level info in not needed, simplt instrument each instruction
//         INS_AddInstrumentFunction(Instruction, 0);
#endif //end  IP_AND_CCT    
        
        // capture write or other sys call that read from user space
        PIN_AddSyscallEntryFunction(SyscallEntry, 0);
        
        
        // Add a function to report entire stats at the termination.
        PIN_AddFiniFunction(Fini, 0);
        
        // Register ImageUnload to be called when an image is unloaded
        IMG_AddUnloadFunction(ImageUnload, 0);
        
        // Launch program now
        PIN_StartProgram();
        return 0;        
    }

