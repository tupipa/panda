

#include <stdio.h>
#include <stdlib.h>
//#include "pin.H"
#include <map>
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
#include <string.h>
#include <setjmp.h>
#include <sstream>
// Need GOOGLE sparse hash tables
#include <google/sparse_hash_map>
#include <google/dense_hash_map>
using google::sparse_hash_map;      // namespace where class lives by default
using google::dense_hash_map;      // namespace where class lives by default
using namespace __gnu_cxx;
using namespace std;

 //else // no MULTI_THREADED

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

//#endif // end MULTI_THREADED


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
    
    
    int main(int argc, char *argv[]) {
        
        // Initialize PIN
        if (PIN_Init(argc, argv))
            return Usage();
        
        // Initialize Symbols, we need them to report functions and lines
        PIN_InitSymbols();
        
        // Intialize DeadSpy
        InitDeadSpy(argc, argv);
        
        
#ifdef IP_AND_CCT
        // Register for context change in case of signals .. Actually this is never used. // Todo: - fix me
        PIN_AddContextChangeFunction(OnSig, 0);
        
        // Instrument the entry to each "known" function. Some functions may not be known
        RTN_AddInstrumentFunction(InstrumentFunctionEntry,0);
        
        // Since some functions may not be known, instrument every "trace"
        TRACE_AddInstrumentFunction(InstrumentTrace,0);
#else //no IP_AND_CCT        
        //IP_AND_CCT case calls via TRACE_AddInstrumentFunction
        
        // When line level info in not needed, simplt instrument each instruction
        INS_AddInstrumentFunction(Instruction, 0);
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

