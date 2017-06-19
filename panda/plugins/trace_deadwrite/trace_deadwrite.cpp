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
            TraceNode,
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
        - InstrumentTraceEntry() : get function info
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
                - ImageUnload()
                - Fini()
        - Update gCurrentIpVector, the array store all IPs for mem WRITE under the current ContextNode
            - on each new mem W detected, 
}

    ==========================

TODO:
    debug modes:
        - no multi thread, with IP and CCT enabled
        - multi thread enable.
    debug stages:
        - mem_call_back() one call iteration.
        - report dead
        - print dead

 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro

//#if defined(TARGET_X86_64)

#define __STDC_FORMAT_MACROS

#include <cstdio>
#include <cstdlib>
#include <ctype.h>
#include <math.h>
#include <map>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>

//Lele: for deadspy
//#include <ext/hash_map>
#include <tr1/unordered_map>
#include <sys/types.h>
#include <stdlib.h>
#include <list>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
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


#include "panda/plugin.h"

extern "C" {
// #include "trace_mem.h"
#include "trace_deadwrite.h"
}

#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

using namespace __gnu_cxx;

using namespace std;
using namespace std::tr1;




// ######################################################
// ######################################################
// ########## Part 1.0: Macros Definitions ##############
// ######################################################
// ######################################################


//lele: make it comparable for the legacy codes from deadspy.cpp in PIN
#define ADDRINT target_ulong
#define USIZE target_ulong
#define UINT32 uint32_t
#define VOID void

//lele: TODO: could be passed as an argument by user
#define CONTINUOUS_DEADINFO
#define IP_AND_CCT

//#define IP_AND_CCT
//#define MERGE_SAME_LINES	
//#define TESTING_BYTES
#define GATHER_STATS
//MT
// #define MULTI_THREADED

// All globals
#define CONTEXT_TREE_VECTOR_SIZE (10)
#define MAX_CCT_PRINT_DEPTH (20)
#define MAX_FILE_PATH   (200)
#ifndef MAX_DEAD_CONTEXTS_TO_LOG 
#define MAX_DEAD_CONTEXTS_TO_LOG   (1000)
#endif //MAX_DEAD_CONTEXTS_TO_LOG

// 64KB shadow pages
#define PAGE_OFFSET_BITS (16LL)
#define PAGE_OFFSET(addr) ( addr & 0xFFFF)
#define PAGE_OFFSET_MASK ( 0xFFFF)

#define PAGE_SIZE (1 << PAGE_OFFSET_BITS)

// 2 level page table
#define PTR_SIZE (sizeof(struct Status *))
#define LEVEL_1_PAGE_TABLE_BITS  (20)
#define LEVEL_1_PAGE_TABLE_ENTRIES  (1 << LEVEL_1_PAGE_TABLE_BITS )
#define LEVEL_1_PAGE_TABLE_SIZE  (LEVEL_1_PAGE_TABLE_ENTRIES * PTR_SIZE )

#define LEVEL_2_PAGE_TABLE_BITS  (12)
#define LEVEL_2_PAGE_TABLE_ENTRIES  (1 << LEVEL_2_PAGE_TABLE_BITS )
#define LEVEL_2_PAGE_TABLE_SIZE  (LEVEL_2_PAGE_TABLE_ENTRIES * PTR_SIZE )

#define LEVEL_1_PAGE_TABLE_SLOT(addr) ((((uintptr_t)addr) >> (LEVEL_2_PAGE_TABLE_BITS + PAGE_OFFSET_BITS)) & 0xfffff)
#define LEVEL_2_PAGE_TABLE_SLOT(addr) ((((uintptr_t)addr) >> (PAGE_OFFSET_BITS)) & 0xFFF)


// have R, W representative macros
#define READ_ACTION (0) 
#define WRITE_ACTION (0xff) 

#define ONE_BYTE_READ_ACTION (0)
#define TWO_BYTE_READ_ACTION (0)
#define FOUR_BYTE_READ_ACTION (0)
#define EIGHT_BYTE_READ_ACTION (0)

// #define ONE_BYTE_WRITE_ACTION (0xff)
// #define TWO_BYTE_WRITE_ACTION (0xffff)
// #define FOUR_BYTE_WRITE_ACTION (0xffffffff)
// #define EIGHT_BYTE_WRITE_ACTION (0xffffffffffffffff)

#define ONE_BYTE_WRITE_ACTION (0xff)
#define TWO_BYTE_WRITE_ACTION (0xffff)
#define FOUR_BYTE_WRITE_ACTION (0xffffffff)
#define EIGHT_BYTE_WRITE_ACTION (0xffffffffffffffff)


#if defined(CONTINUOUS_DEADINFO)

// make 64bit hash from 2 32bit deltas from 
// remove lower 3 bits so that when we need more than 4 GB HASH still continues to work

#define CONTEXT_HASH_128BITS_TO_64BITS(curCtxt, oldCtxt, hashVar)  \
{\
uint64_t key = (uint64_t) (((void**)oldCtxt) - gPreAllocatedContextBuffer); \
hashVar = key << 32;\
key = (uint64_t) (((void**)curCtxt) - gPreAllocatedContextBuffer); \
hashVar |= key;\
}

#else // no defined(CONTINUOUS_DEADINFO)

#define CONTEXT_HASH_128BITS_TO_64BITS(curCtxt, oldCtxt, hashVar)  \
{\
uint64_t key = (uint64_t) curCtxt; \
key = (~key) + (key << 18);\
key = key ^ (key >> 31);\
key = key * 21;\
key = key ^ (key >> 11);\
key = key + (key << 6);\
key = key ^ (key >> 22);\
hashVar = (uint64_t) (key << 32);\
key = (uint64_t) (oldCtxt);\
key = (~key) + (key << 18);\
key = key ^ (key >> 31);\
key = key * 21; \
key = key ^ (key >> 11);\
key = key + (key << 6);\
key = key ^ (key >> 22);\
hashVar = hashVar | ((int) key);\
}

#endif // end defined(CONTINUOUS_DEADINFO)



#ifdef IP_AND_CCT
#define OLD_CTXT (*lastIP)
#ifndef MULTI_THREADED
#define CUR_CTXT (&gCurrentIpVector[slot])
#else // no MULTI_THREADED
#define CUR_CTXT (assert( 0 && " NYI"))
#endif // end of ifndef MULTI_THREADED
#else // else IP_AND_CCT
#define OLD_CTXT (*lastIP)

#ifndef MULTI_THREADED
#define CUR_CTXT (gCurrentContext)
#else //MULTI_THREADED
#define CUR_CTXT (gContextTreeVector[PIN_ThreadId()].currentContext)
#endif // end of ifndef MULTI_THREADED

#endif // end of IP_AND_CCT




// NO FALSE NEGATIVES is always defined 


#if defined(CONTINUOUS_DEADINFO)

#define DECLARE_HASHVAR(name) uint64_t name

#define REPORT_DEAD(curCtxt, lastCtxt,hashVar, size) do { \
CONTEXT_HASH_128BITS_TO_64BITS(curCtxt, lastCtxt,hashVar)  \
if ( (gDeadMapIt = DeadMap.find(hashVar))  == DeadMap.end()) {    \
DeadMap.insert(std::pair<uint64_t, uint64_t>(hashVar,size)); \
} else {    \
(gDeadMapIt->second) += size;    \
}   \
printf("report one dead %lu (%d)", hashVar,size); \
}while(0)

#else // no defined(CONTINUOUS_DEADINFO)
#define DECLARE_HASHVAR(name) uint64_t name

#define REPORT_DEAD(curCtxt, lastCtxt,hashVar, size) do { \
CONTEXT_HASH_128BITS_TO_64BITS(curCtxt, lastCtxt,hashVar)  \
if ( (gDeadMapIt = DeadMap.find(hashVar))  == DeadMap.end()) {    \
DeadInfo deadInfo = { lastCtxt,  curCtxt, size };   \
DeadMap.insert(std::pair<uint64_t, uint64_t>(hashVar,deadInfo)); \
} else {    \
(gDeadMapIt->second.count) += size;    \
}   \
}while(0)

#endif // end defined(CONTINUOUS_DEADINFO)

#define REPORT_IF_DEAD(mask, curCtxt, lastCtxt, hashVar) do {if (state & (mask)){ \
REPORT_DEAD(curCtxt, lastCtxt,hashVar, 1);\
}}while(0)


#ifdef TESTING_BYTES
#define RecordNByteMemWrite(type, size, sizeSTR) do{\
uint8_t * status = GetOrCreateShadowBaseAddress(addr);\
if(PAGE_OFFSET((uintptr_t)addr) <  (PAGE_OFFSET_MASK - size - 2)){\
type state = *((type*)(status +  PAGE_OFFSET((uintptr_t)addr)));\
if ( state != sizeSTR##_BYTE_READ_ACTION) {\
if (state == sizeSTR##_BYTE_WRITE_ACTION) {\
gFullyKilling##size ++;\
} else {\
gPartiallyKilling##size ++;\
for(type s = state; s != 0 ; s >>= 8)\
if(s & 0xff)\
gPartiallyDeadBytes##size++;\
}\
} \
*((type* )(status +  PAGE_OFFSET((uintptr_t)addr))) = sizeSTR##_BYTE_WRITE_ACTION;\
} else {\
type state = *((uint8_t*)(status +  PAGE_OFFSET((uintptr_t)addr)));        \
*((uint8_t*)(status +  PAGE_OFFSET((uintptr_t)addr))) = ONE_BYTE_WRITE_ACTION;\
uint8_t deadBytes =  state == ONE_BYTE_WRITE_ACTION ? 1 :0;\
for(uint8_t i = 1 ; i < size; i++){\
status = GetOrCreateShadowBaseAddress(((char *) addr ) + i);            \
state = *((uint8_t*)(status +  PAGE_OFFSET((((uintptr_t)addr) + i))));\
if(state == ONE_BYTE_WRITE_ACTION)\
deadBytes++;            \
*((uint8_t*)(status +  PAGE_OFFSET((((uintptr_t)addr) + i)))) = ONE_BYTE_WRITE_ACTION;\
}\
if(deadBytes == size)\
gFullyKilling##size ++;\
else if(deadBytes){\
gPartiallyKilling##size ++;\
gPartiallyDeadBytes##size += deadBytes;\
}        \
}\
}while(0)

#endif // end TESTING_BYTES




// ######################################################
// ######################################################
// ########## Part 1.1: Variable/Struct Definitions #####
// ######################################################
// ######################################################


#ifndef MULTI_THREADED
target_ulong g1ByteWriteInstrCount;
target_ulong g2ByteWriteInstrCount;
target_ulong g4ByteWriteInstrCount;
target_ulong g8ByteWriteInstrCount;
target_ulong g10ByteWriteInstrCount;
target_ulong g16ByteWriteInstrCount;
target_ulong gLargeByteWriteInstrCount;
target_ulong gLargeByteWriteByteCount;
#endif

#ifdef TESTING_BYTES 
target_ulong gFullyKilling1;
target_ulong gFullyKilling2;
target_ulong gFullyKilling4;
target_ulong gFullyKilling8;
target_ulong gFullyKilling10;
target_ulong gFullyKilling16;
target_ulong gFullyKillingLarge;

target_ulong gPartiallyKilling1;
target_ulong gPartiallyKilling2;
target_ulong gPartiallyKilling4;
target_ulong gPartiallyKilling8;
target_ulong gPartiallyKilling10;
target_ulong gPartiallyKilling16;
target_ulong gPartiallyKillingLarge;

target_ulong gPartiallyDeadBytes1;
target_ulong gPartiallyDeadBytes2;
target_ulong gPartiallyDeadBytes4;
target_ulong gPartiallyDeadBytes8;
target_ulong gPartiallyDeadBytes10;
target_ulong gPartiallyDeadBytes16;
target_ulong gPartiallyDeadBytesLarge;
#endif // end TESTING_BYTES


struct ContextNode;
struct DeadInfo;


FILE *gTraceFile = NULL;
FILE *gTraceFile_user = NULL;
// FILE *gTraceFile;
// FILE *gTraceFile_user;

#ifdef IP_AND_CCT
struct MergedDeadInfo;
struct TraceNode;
struct DeadInfoForPresentation;
inline ADDRINT GetIPFromInfo(void * ptr);
inline string GetLineFromInfo(void * ptr);
#endif // end IP_AND_CCT


#ifdef CONTINUOUS_DEADINFO
//#define PRE_ALLOCATED_BUFFER_SIZE (1L << 35)
// default use this
#define PRE_ALLOCATED_BUFFER_SIZE (1L << 32)
void ** gPreAllocatedContextBuffer;
target_ulong gCurPreAllocatedContextBufferIndex;
#endif //end CONTINUOUS_DEADINFO

struct ContextNode {
    ContextNode * parent;
    sparse_hash_map<ADDRINT,ContextNode *> childContexts;
#ifdef IP_AND_CCT
    sparse_hash_map<ADDRINT,TraceNode *> childTraces;
    // TraceNode * childTrace;
#endif // end IP_AND_CCT    
    ADDRINT address;
    
#if defined(CONTINUOUS_DEADINFO) && !defined(IP_AND_CCT) 
    void* operator new (size_t size) {
        ContextNode  * ret =  ((ContextNode*)gPreAllocatedContextBuffer) + gCurPreAllocatedContextBufferIndex;
        gCurPreAllocatedContextBufferIndex ++;
        assert( gCurPreAllocatedContextBufferIndex  < (PRE_ALLOCATED_BUFFER_SIZE)/size);
        return ret;
    }
#endif //end  defined(CONTINUOUS_DEADINFO) && !defined(IP_AND_CCT)    
    
};


#ifdef IP_AND_CCT
struct MergedDeadInfo{
	ContextNode * context1;
	ContextNode * context2;
#ifdef MERGE_SAME_LINES
	string line1;
	string line2;
#else    // no MERGE_SAME_LINES
	ADDRINT ip1;
	ADDRINT ip2;
#endif // end MERGE_SAME_LINES
    
	bool operator==(const MergedDeadInfo  & x) const{
#ifdef MERGE_SAME_LINES
		if ( this->context1 == x.context1 && this->context2 == x.context2 &&
            this->line1 == x.line1 && this->line2 == x.line2)
#else            // no MERGE_SAME_LINES
            if ( this->context1 == x.context1 && this->context2 == x.context2 &&
				this->ip1 == x.ip1 && this->ip2 == x.ip2)
#endif //end MERGE_SAME_LINES
                return true;
		return false;
	}
    
    bool operator<(const MergedDeadInfo & x) const {
#ifdef MERGE_SAME_LINES
        if ((this->context1 < x.context1) ||
            (this->context1 == x.context1 && this->context2 < x.context2) ||
            (this->context1 == x.context1 && this->context2 == x.context2 && this->line1 < x.line1) ||
            (this->context1 == x.context1 && this->context2 == x.context2 && this->line1 == x.line1 && this->line2 < x.line2) )
#else            // no MERGE_SAME_LINES
            if ((this->context1 < x.context1) ||
                (this->context1 == x.context1 && this->context2 < x.context2) ||
                (this->context1 == x.context1 && this->context2 == x.context2 && this->ip1 < x.ip1) ||
                (this->context1 == x.context1 && this->context2 == x.context2 && this->ip1 == x.ip1 && this->ip2 < x.ip2) )
#endif // end  MERGE_SAME_LINES               
                return true;
        return false;
	}
    
};

struct DeadInfoForPresentation{
    const MergedDeadInfo * pMergedDeadInfo;
    target_ulong count;
};

struct TraceNode{
    ContextNode * parent;
    TraceNode ** childIPs;
    ADDRINT address;
    uint32_t nSlots;
};

#endif // end IP_AND_CCT

struct DeadInfo {
	void *firstIP;
	void *secondIP;
	target_ulong count;
};

uint8_t ** gL1PageTable[LEVEL_1_PAGE_TABLE_SIZE];

//map < void *, Status > MemState;
#if defined(CONTINUOUS_DEADINFO)
//hash_map<uint64_t, uint64_t> DeadMap;
//hash_map<uint64_t, uint64_t>::iterator gDeadMapIt;
unordered_map<uint64_t, uint64_t> DeadMap;
unordered_map<uint64_t, uint64_t>::iterator gDeadMapIt;

#endif // end defined(CONTINUOUS_DEADINFO)


#define REPORT_IF_DEAD(mask, curCtxt, lastCtxt, hashVar) do {if (state & (mask)){ \
REPORT_DEAD(curCtxt, lastCtxt,hashVar, 1);\
}}while(0)



#ifdef GATHER_STATS
FILE *statsFile;
#endif //end GATHER_STATS

target_ulong gTotalDead = 0;
#ifdef MULTI_THREADED
target_ulong gTotalMTDead = 0;
#endif // end MULTI_THREADED


// SEGVHANDLEING FOR BAD .plt
// Lele: cmt this for panda
jmp_buf env;
//struct sigaction gSigAct;
//void SegvHandler(int);

ContextNode * gRootContext;
ContextNode * gCurrentContext;
sparse_hash_map<ADDRINT, ContextNode *>::iterator gContextIter;

/// MT 
#ifdef MULTI_THREADED

// Multi threaded codes keep counters in each CCT
struct ContextTree{
    ContextNode * rootContext;
    ContextNode * currentContext;
    
    target_ulong mt1ByteWriteInstrCount;
    target_ulong mt2ByteWriteInstrCount;
    target_ulong mt4ByteWriteInstrCount;
    target_ulong mt8ByteWriteInstrCount;
    target_ulong mt10ByteWriteInstrCount;
    target_ulong mt16ByteWriteInstrCount;
    target_ulong mtLargeByteWriteInstrCount;
    target_ulong mtLargeByteWriteByteCount;
    
    
};
vector<ContextTree> gContextTreeVector;
#endif //end MULTI_THREADED



#ifdef IP_AND_CCT
sparse_hash_map<ADDRINT, TraceNode *>::iterator gTraceIter;
//dense_hash_map<ADDRINT, void *> gTraceShadowMap;
// hash_map<ADDRINT, void *> gTraceShadowMap;
//Lele: we don't use StartAddr of a trace as key, instead, we use ContextNode's address as key, to store an array, doing the same thing: ---mapping the slots index of each write instruction in a function to its corresponding IP. In order to be compatible with the legacy TraceNode, we use one tracenode to store the array, with StartAddr equal to the ContextNodes' address.
unordered_map<ADDRINT, void *> gTraceShadowMap;
TraceNode * gCurrentTrace;
uint32_t gCurrentSlot;

bool gInitiatedCall = true;
bool gInitiatedRet = true;
TraceNode ** gCurrentIpVector;
ADDRINT gCurrentCallerIp;

bool gTraceKernel=false; //trace all kernel processes; asid=0
bool gTraceApp=false; // trace all other asids !=0;
bool gTraceOne = false; //trace only one given ASID, kernel=0, or other asids. If this is true, the 'traceKernel' and 'traceApp' is invalide; If ASID not given, default is 0.
ADDRINT gCurrentASID=0x0; //only valide if traceOne is true;

uint32_t gContextTreeIndex;

struct ContextTree{
    ContextNode * rootContext;
    ContextNode * currentContext;
};
vector<ContextTree> gContextTreeVector;

VOID GoDownCallChain(ADDRINT);
VOID UpdateDataOnFunctionEntry(ADDRINT currentIp);
// VOID Instruction(INS ins, uint32_t slot);

#endif //IP_AND_CCT

// Silly: since we use these as map values, they have to be
// copy constructible. Plain arrays aren't, but structs containing
// arrays are. So we make these goofy wrappers.
struct match_strings {
    int val[MAX_STRINGS];
};

char trace_file_kernel[128] = {};
char trace_file_user[128] = {};


struct string_pos {
    uint32_t val[MAX_STRINGS];
};
struct CallStack {
    int n;
    target_ulong addr;
    target_ulong callers[MAX_CALLERS];
    target_ulong pc;
    target_ulong asid;
};

// std::map<prog_point,CallStack> matchstacks;
// std::map<prog_point,CallStack> matchstacks_user;
// std::map<prog_point,match_strings> matches;
// std::map<prog_point,string_pos> read_text_tracker;
// std::map<prog_point,string_pos> write_text_tracker;
// uint8_t tofind[MAX_STRINGS][MAX_STRLEN];
// uint32_t strlens[MAX_STRINGS];
// int num_strings = 0;
int n_callers = 16;


// ######################################################
// ######################################################
// ########## Part 1.2: Function Declarations ###########
// ######################################################
// ######################################################

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void init_deadspy();
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

// prototype for the register-this-callback fn
//PPP_PROT_REG_CB(on_ssm);
//PPP_PROT_REG_CB(on_deadwrite);

}

inline bool MergedDeadInfoComparer(const DeadInfoForPresentation & first, const DeadInfoForPresentation  &second);
inline bool DeadInfoComparer(const DeadInfo &first, const DeadInfo &second);
inline bool IsValidIP(ADDRINT ip);
inline bool IsValidIP(DeadInfo  di);


// ######################################################
// ######################################################
// ########## Part 2.1: Function Definitions ############
// ######################################################
// ######################################################




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
#endif //end CONTINUOUS_DEADINFO



#ifdef IP_AND_CCT

// Analysis routine called on entering a function (found in symbol table only)
inline VOID UpdateDataOnFunctionEntry(ADDRINT currentIp){
    
    // if I enter here due to a tail-call, then we will make it a child under the parent context node
    if (!gInitiatedCall){
        printf("a tailer call?\n");
        gCurrentContext = gCurrentContext->parent;
    } else {
        // normal function call, so unset gInitiatedCall
        printf("get a new function call !\n");
        gInitiatedCall = false;
    }
    
    // Let GoDownCallChain do the work needed to setup pointers for child nodes.
    GoDownCallChain(currentIp);
    
}


// // Analysis routine called on making a function call
// inline VOID SetCallInitFlag(){
//     gInitiatedCall = true;
// }


// // Instrumentation for the function entry (found in symbol table only).
// // Get the first instruction of the first BBL and insert call to the analysis routine before it.

// inline VOID InstrumentFunctionEntry(RTN rtn, void *f){
//     RTN_Open(rtn);
//     INS ins = RTN_InsHeadOnly(rtn);
//     INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)UpdateDataOnFunctionEntry, IARG_INST_PTR,IARG_END);
//     RTN_Close(rtn);    
// }
#endif //end IP_AND_CCT

// MT
#ifndef MULTI_THREADED

// Analysis routine called on function entry. 
// If the target IP is a child, make it gCurrentContext, else add one under gCurrentContext and point gCurrentContext to the newly added

VOID GoDownCallChain(ADDRINT callee){
    printf(__FUNCTION__);
    printf("\n");
    if( ( gContextIter = (gCurrentContext->childContexts).find(callee)) != gCurrentContext->childContexts.end()) {
        gCurrentContext = gContextIter->second;
    } else {
        ContextNode * newChild =  new ContextNode();
        newChild->parent = gCurrentContext;
        newChild->address = callee;
        gCurrentContext->childContexts[callee] = newChild;
        gCurrentContext = newChild;
    }
}

// Analysis routine called on function return. 
// Point gCurrentContext to its parent, if we reach the root, set gInitiatedCall.//lele: why?

inline VOID GoUpCallChain(){
#ifdef IP_AND_CCT
    //assert(gCurrentContext->parent && "NULL PARENT CTXT");
    
    if (gCurrentContext->parent == gRootContext) {
        // gInitiatedCall = true;//lele: why?
        printf("lele: ret to root context node\n");
    }
    gCurrentContext = gCurrentContext->parent;
    
    // RET & CALL end a trace hence the target should trigger a new trace entry for us ... pray pray.
    
#else    // no IP_AND_CCT
    gCurrentContext = gCurrentContext->parent;
#endif    //end IP_AND_CCT
    
}
#else // MULTI_THREADED

// Analysis routine called on function entry. 
// If the target IP is a child, make it gContextTreeVector[pinTID].currentContext, else add one under gContextTreeVector[pinTID].currentContext and point gContextTreeVector[pinTID].currentContext to the newly added

VOID GoDownCallChain(ADDRINT callee){
    
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

inline VOID ManageCallingContext(CallStack *fstack){
#ifdef TESTING_BYTES
	return; // no CCT
#endif // end TESTING_BYTES
    
    // manage context
    // lele: need to write new functions and methods to manage context
    // generally: 
    //  1, we use context node and ip slots solution, don't use any trace nodes.(But during adaption, we use only on TraceNode with ContextNode's IP as key)
    //  This would reduce lots of overhead compared to Trace solution in PIN Deadspy. At least there is only one array store write IPs instead of many Trace Nodes.
    //  2, we need to detect current context change by prog_point info and update our CCT by goDown/goUp;
    //
    //lele: check and detect a function call boundaries by comparing the CallStack with the current call CCT.
    // if context node of currentIp is the last one of the caller stack. No func call is initiated.
    // if context node of currentIp is the second last of the caller stack. New func call has been done.
    // Otherwise, if current context node doesn't exists in the caller stack. Distinguish it by the last one of the call stack.
    //  - a ret : last caller is the parent of current context node.
    //  - a new func call : last caller is not the parent of current context node.

    // if an function call, continue with trace entry method from PIN deadspy, otherwise, return.


    //printf("step 1/3: detect whether in new func\n");
    //#################################################
    //################# step 1/3, detect whether in ####
    //  - current function, iff curContextNode is the same with last of caller stack, or 
    //                         caller stack size is zero and curContextNode is the same with root of ContextNode.
    //      - just return in this case, do nothing to context nodes.
    //
    //  - a ret function, iff curContextNode doesn't exists in call stack but last caller is the parent of the current context node.
    //      -call goUpCallChain to update curContextNode.
    //
    //  - a new function call, iff curContextNode is the same with second last of caller stack, or 
    //                              curContextNode is not in the call stack and laster caller is not the parent of current context node(WRONG/IMP CASE).
    //      -call goDownCallChain to create new ContextNode
    //
    // we don't detect function call directly. 
    // we find a new function by comparing the last function in call stack with the current function.
    gInitiatedCall = false;
    gInitiatedRet = false;

    ADDRINT curContextIp = gCurrentContext->address;
    ADDRINT parContextIp;

    // ADDRINT currentIp = fstack->pc;
    ADDRINT callerIp, callerCallerIp;

    
    printf("curContextIp: " TARGET_FMT_lx "\n", curContextIp);
    if (fstack->n < 0){
            printf("ERROR: get neg callers.\n");
            exit(-1);

    }else if (fstack->n == 0){
        // no callers, must be in current func
        //printf("%s: get 0 callers\n", __FUNCTION__);
        if (gCurrentContext != gRootContext  && gCurrentContext-> parent != gRootContext){
            //when no func, gCurrentContext or its parent must be equal with gRootContext
            printf("ERROR: when no func, gCurrentContext must point to gRootContext!!!\n");
            exit(-1);
        }else if (gCurrentContext-> parent == gRootContext){
            gInitiatedRet = true;
            printf("return to no func level!!\n");
        //}else{
            //printf("GOOD: init, no function yet!\n");
        }
        callerIp=gCurrentCallerIp;

        //keep gInitatedCall to be false in this case;
    }else {
        // call stack has at least one element, could be three cases:
        // - current func
        // - a new func
        // - a ret 

        // get last caller's ip
        callerIp = fstack->callers[CALLERS_LAST];
        printf("get callerIp on stack: " TARGET_FMT_lx "\n", callerIp);
        gCurrentCallerIp= callerIp;
        // callerIp = fstack->callers[0];
        if(fstack->n == 1){
            printf("first level function ever!!!\n");
        }

        // detect in current func by compare last caller with current Context.
        if (curContextIp == callerIp){
            //no new call if last caller is the same with current Context.
            gInitiatedCall = false;
            printf("no new call, do nothing.\n");
            return;
        }else{
            // now curContextIp is not last caller, two cases:
            // a ret, or a new func call
            if(fstack->n == 1){
                //in first level function; if gCurrentContext pointed to root, then should be in new function
                if (gCurrentContext == gRootContext){
                    printf("Entered first level function from root!\n");
                    // callerIp is first level's func; move currentContext to this func;
                    // create one child of RootContext
                    gInitiatedCall = true;
                }else{
                    printf("gCurrentContext is not root; instruction is in first level func; so not new func. Do nothing.\n");
                }
            }else{
                //in other level functions:
                // - a new func call, curContextNode is the second last of call stack, or
                //                    curContextNode is not the second last of call stack, neither it's parent is the last one in call stack, but in the second last is it's parent.
                // - a ret, curContextNode is not the second last of call stack, but it's parent is the last in call stack.
                callerCallerIp = fstack->callers[CALLERS_SECOND_LAST];
                if (curContextIp == callerCallerIp){
                    // current Context is the second last of call stack, enter a new func.
                    // curContext will become the parent of this new func.
                    // first detect whether this func is already a children of currentContext. if not, create one.
                    // set cur context with callerIp.
                    gInitiatedCall=true;
                    printf("curContext is equal to caller of the caller; so new call detected\n");
                }else {
                    // current Context is neither the last nor the second last in the call stack.
                    // - a ret: current Context's parent is the last in call stack.
                    // WRONG: current Context's parent is not the last in call stack.
                    // //curContext is impossible to be root when there are more than one callers in stack.
                    if (gCurrentContext == gRootContext){
                        printf("Error: current context node should not be root context when there are >2 callers in stack. A new context should be created when there is 1 callers in stack.\n");
                    }
                    ContextNode * parContext = gCurrentContext->parent;
                    // parContext is impossible to be root: parent context must be last in call stack, so should not be the root.
                    // when parent of the cur context node is the root, it's in the first func, call stack is at most 2 callers where cur context is the second last in call stack.
                    parContextIp = parContext->address;

                    if(parContextIp == callerIp){
                        gInitiatedRet = true;
                        printf("parent ContextIp is equal to the caller Ip, a ret detected. \n");
                    }else{
                        printf("Error: callers>=2: current Context is neither the last nor the second last in the call stack, and current Context's parent is not the last in call stack.\n");
                        exit(-1);
                    }
                }
            }

        }
        
    }

    // ###################################################
    // ################### step 2/3, #####################
    // ###################################################
    //  - create Context Node when new func call; 
    //  - store IP to shadow pages
    //  to simulate the PopulateIPReverseMapAndAccountTraceInstructions() on every new func call, which had store IPs for all 
    //  Instructions
    //  - reset slot to 0.
    //  - add current pc as first instruction in ip

    //printf("step 2/3: create Context Node when new func call\n");
    
    ////////////////////////////////////
    // InstrumentTrace(TRACE trace, void * f):
    //   BBL bbl = TRACE_BblHead(trace);
    //   INS ins = BBL_InsHead(bbl);
    //   INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)InstrumentTraceEntry,IARG_INST_PTR,IARG_END);    
    //   PopulateIPReverseMapAndAccountTraceInstructions(trace);

    // // Does necessary work on a trace entry (called during runtime)
    // // 1. If landed here due to function call, then go down in CCT.
    // // 2. Look up the current trace under the CCT node creating new if if needed.
    // // 3. Update global iterators and curXXXX pointers.

    // inline void InstrumentTraceEntry(ADDRINT currentIp){
        
    // if landed due to function call, create a child context node

    if(gInitiatedCall){
        // gInitatedCall = true, means this mem R/W instruction is inside a new function call
        // So, we need to:
        //  - update the CCT with a new Context Node and 
        //  - update corresponding array slot index to store the new IP with mem W (no read)
        //
        // a new function call is on the top of call stack.
        printf("gInitiatedCall=true\n");

        UpdateDataOnFunctionEntry(callerIp); // it will reset   gInitiatedCall  

        printf("setup according to PopulateIPReverseMapAndAccountTraceInstructions() in deadspy\n");
        //uint32_t traceSize = TRACE_Size(trace);    
        uint32_t traceSize = 0x80;    //lele: TODO: determine the size of function
     
        ADDRINT * ipShadow = (ADDRINT * )malloc( (1 + traceSize) * sizeof(ADDRINT)); // +1 to hold the number of slots as a metadata
        ADDRINT  traceAddr = callerIp;
        uint32_t slot = 0;
    
        gCurrentSlot = slot;
    
        // give space to account for nSlots which we record later once we know nWrites
        ADDRINT * pNumWrites = ipShadow;
        ipShadow ++;
        gTraceShadowMap[traceAddr] = ipShadow ;

         // Record the number of child write IPs i.e., number of "slots"
        *pNumWrites = slot;

    }else if(gInitiatedRet){
        printf("get a ret; call GoUpCallChain...\n");
        // Let GoDownCallChain do the work needed to setup pointers for child nodes.
        GoUpCallChain();
    }else if (gInitiatedCall && gInitiatedRet){
        printf("ERROR: cant ret and call at same time\n");
        exit(-1);
    // }else{
    //     printf("no new call, no ret.\n");
    }
    
    //#######################################################
    // ######################## setp 3/3, #################
    // update currentIp slots for curContextNode. necessary here!
    // lele: we adapt the name of "Trace" to store the slots. Might be improved by using a single TraceNode instead of a map with only one TraceNode.

    // Check if a trace node with currentIp already exists under this context node
    
    //printf("step 3/3, update currentIp slots for curContextNode. necessary here!\n");
    // Check if a trace node with currentIp already exists under this context node    
          
    //printf("callerIp: " TARGET_FMT_lx "\n", callerIp);
    if( (gTraceIter = (gCurrentContext->childTraces).find(callerIp)) != gCurrentContext->childTraces.end()) {
        // if tracenode is already exists
        // set the current Trace to the new trace
        // set the IpVector
        //printf("Trace Node already exists\n");
        gCurrentTrace = gTraceIter->second;
        gCurrentIpVector = gCurrentTrace->childIPs;
        //lele: set slot index
        gCurrentSlot = gCurrentTrace->nSlots;
        printf("Trace Node exists; set/get current slots:%u\n", gCurrentSlot);

     } else {
        //panda: if not in the current context node, this means in a new function and a new context node is created.
        
        // Create new trace node and insert under the context node.
        printf(__FUNCTION__);
        printf(": Need to Create new Trace node.\n");

        TraceNode * newChild = new TraceNode();
        printf("TraceNode New Child Created\n");
        printf("\tNew Child: set parent\n");
        newChild->parent = gCurrentContext;
        printf("\tNew Child: set address\n");
        newChild->address = callerIp;
        printf("get currentTraceShadowIp from gTraceShadowMap[callerIp]\n");
    	target_ulong * currentTraceShadowIP = (target_ulong *) gTraceShadowMap[callerIp];
        printf("get recordedSlots from currentTraceShadowIP[-1] %p\n", currentTraceShadowIP);
        target_ulong recordedSlots = currentTraceShadowIP[-1]; // present one behind
        if(recordedSlots){
            printf("Record Slots: " TARGET_FMT_lx "\n", recordedSlots);
#ifdef CONTINUOUS_DEADINFO
            // if CONTINUOUS_DEADINFO is set, then all ip vecs come from a fixed 4GB buffer
            printf("Continuous Info: GetNextIPVecBuffer...\n");
            newChild->childIPs  = (TraceNode **)GetNextIPVecBuffer(recordedSlots);
#else            //no CONTINUOUS_DEADINFO
            printf("NON Continuous Info: malloc new TraceNode**\n");
            newChild->childIPs = (TraceNode **) malloc( (recordedSlots) * sizeof(TraceNode **) );
#endif //end CONTINUOUS_DEADINFO
            newChild->nSlots = recordedSlots;
            //cerr<<"\n***:"<<recordedSlots; 
            for(uint32_t i = 0 ; i < recordedSlots ; i++) {
                newChild->childIPs[i] = newChild;
            }
        } else {
            printf("No record slots read\n");
            newChild->nSlots = 0;
            newChild->childIPs = 0;            
        }    
        gCurrentContext->childTraces[callerIp] = newChild;
        gCurrentTrace = newChild;
        gCurrentIpVector = gCurrentTrace->childIPs;
        //lele: set slot index
        gCurrentSlot = gCurrentTrace->nSlots;
    }    

//     if(INS_IsProcedureCall(ins) ) {
// #ifdef IP_AND_CCT
//         INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) SetCallInitFlag,IARG_END);
// #else        // no IP_AND_CCT        
//         INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) GoDownCallChain, IARG_BRANCH_TARGET_ADDR, IARG_END);
// #endif // end IP_AND_CCT        
//     }else if(INS_IsRet(ins)){
//         INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) GoUpCallChain, IARG_END);
//     }
    printf("%s: done manage context for one memory operating instruction\n\n", __FUNCTION__);
}





//// MT
#ifndef MULTI_THREADED 

// Initialized the fields of the root node of all context trees
VOID InitContextTree(){
    //gCurrentASID = 0x0; 
    //gTraceKernel=true;
    gTraceApp=true;
    //gTraceOne=true;
    //gCurrentASID = 0x000000001fb14000;
     
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

    printf("init setup according to PopulateIPReverseMapAndAccountTraceInstructions() in deadspy\n");
        //uint32_t traceSize = TRACE_Size(trace);    
    uint32_t traceSize = 0x80;    //lele: TODO: determine the size of function
    ADDRINT * ipShadow = (ADDRINT * )malloc( (1 + traceSize) * sizeof(ADDRINT)); // +1 to hold the number of slots as a metadata
    ADDRINT  traceAddr = 0;
    uint32_t slot = 0;
    
    gCurrentSlot = slot;
    gCurrentCallerIp = 0x0;
    
    // give space to account for nSlots which we record later once we know nWrites
    ADDRINT * pNumWrites = ipShadow;
    ipShadow ++;
    gTraceShadowMap[traceAddr] = ipShadow ;

    // Record the number of child write IPs i.e., number of "slots"
    *pNumWrites = slot;

    printf("done. init setup according to PopulateIPReverseMapAndAccountTraceInstructions() in deadspy\n");
   
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
    printf("%s\n",__FUNCTION__);
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
        
        // TODO:lele only supports 64bit here.
        if (sizeof(state) == 8 && state != EIGHT_BYTE_READ_ACTION) {
            DECLARE_HASHVAR(myhash);
            void * ipZero = lastIP[0];
            // fast path where all bytes are dead by same context
            // TODO:lele only supports 64bit here.
            if ( sizeof(state) == 8 && state == EIGHT_BYTE_WRITE_ACTION &&
                ipZero  == lastIP[1] && ipZero  == lastIP[2] &&
                ipZero  == lastIP[3] && ipZero  == lastIP[4] &&
                ipZero  == lastIP[5] && ipZero  == lastIP[6] && ipZero  == lastIP[7] ) {
                REPORT_DEAD(CUR_CTXT, ipZero, myhash, 8);
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
    cerr<<"\n"<<addr<<":"<<sz;
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


// this creates BOTH the global for this callback fn (on_ssm_func)
// and the function used by other plugins to register a fn (add_on_ssm)
//PPP_CB_BOILERPLATE(on_trace_mem_asid)

// this creates the 

int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf, bool is_write
                       //,std::map<prog_point,string_pos> &text_tracker
                       ){
    prog_point p = {};
    get_prog_point(env, &p);

    //lele: filter out the processes(threads?) according to its ASID    
    
    //printf("curASID: " TARGET_FMT_lx "\n", callstack.asid);
    if (gTraceOne){
        if (p.cr3 != gCurrentASID){
            //printf("ignore ASID " TARGET_FMT_lx , p.cr3);
            return 1;
        } else{
            printf("\none mem op for ASID: " TARGET_FMT_lx "\n", gCurrentASID);
        }
    }else if (gTraceKernel){
        if (p.cr3 != 0x0 ){
            //printf("ignore ASID " TARGET_FMT_lx , p.cr3);
            return 1;
        } else{
            printf("\nKernel mem op\n");
        }
    }else if (gTraceApp){
        if (p.cr3 == 0x0 ){
            //printf("ignore ASID " TARGET_FMT_lx , p.cr3);
            return 1;
        } else{
            printf("\nApp mem op, ASID: " TARGET_FMT_lx "\n", p.cr3);
        }
    }else{
        // no filters
        printf("\nAll: Mem op for ASID: " TARGET_FMT_lx "\n", p.cr3);
    }

//    string_pos &sp = text_tracker[p];

//     if(p.cr3 == 0){

// 	//printf("%s\t" TARGET_FMT_lx
//  	//		"\t %lu \t" TARGET_FMT_lx 
// 	//		"\t" TARGET_FMT_lx 
// 	//		"\n",
//         //    (is_write ? "W" : "R"), addr, 
// 	//		rr_get_guest_instr_count(), p.caller,
// 	//		p.pc);

//         // Also get the full stack here
//         CallStack f = {0};
//         f.n = get_callers(f.callers, n_callers, env);
//         f.pc = p.pc;
//         f.asid = p.cr3;


//        // Print prog point
// 	// ORDER:
// 	// W/R	addr callers1 ... callersn pc asid
//        	fprintf(gTraceFile, "%s\t", (is_write ? "W" : "R"));

//        	fprintf(gTraceFile, TARGET_FMT_lx " ", addr);

//         for (int i = f.n-1; i >= 0; i--) {
//             fprintf(gTraceFile, TARGET_FMT_lx " ", f.callers[i]);
//         }
// 	if (f.n == 0){
//             fprintf(gTraceFile, "\tno callers\t");
// 	}

//        	fprintf(gTraceFile, TARGET_FMT_lx " ", f.pc);
//        	fprintf(gTraceFile, TARGET_FMT_lx " ", f.asid);
//         // Print strings that matched and how many times
//         fprintf(gTraceFile, "\n");

//         // call the i-found-a-mem-access-in-asid registered callbacks here
//         //PPP_RUN_CB(on_trace_mem_asid, env, pc, addr, tofind[str_idx], strlens[str_idx], is_write)

//     }else{


// 	//printf("%s\t" TARGET_FMT_lx
//  	//		"\t %lu \t" TARGET_FMT_lx 
// 	//		"\t" TARGET_FMT_lx 
// 	//		"\n",
//         //    (is_write ? "W" : "R"), addr, 
// 	//		rr_get_guest_instr_count(), p.caller,
// 	//		p.pc);

//         // Also get the full stack here
//         CallStack f = {0};
//         f.n = get_callers(f.callers, n_callers, env);
//         f.pc = p.pc;
//         f.asid = p.cr3;


//        // Print prog point
// 	// ORDER:
// 	// W/R	addr callers1 ... callersn pc asid
//        	fprintf(gTraceFile_user, "%s\t", (is_write ? "W" : "R"));

//        	fprintf(gTraceFile_user, TARGET_FMT_lx " ", addr);

//         for (int i = f.n-1; i >= 0; i--) {
//             fprintf(gTraceFile_user, TARGET_FMT_lx " ", f.callers[i]);
//         }
//         if (f.n == 0){
//                 fprintf(gTraceFile_user, "\tno callers\t");
//         }

//        	fprintf(gTraceFile_user, TARGET_FMT_lx " ", f.pc);
//        	fprintf(gTraceFile_user, TARGET_FMT_lx " ", f.asid);
//         // Print strings that matched and how many times
//         fprintf(gTraceFile_user, "\n");


//         // call the i-found-a-mem-access-in-asid registered callbacks here
//         //PPP_RUN_CB(on_trace_mem_asid, env, pc, addr, tofind[str_idx], strlens[str_idx], is_write)
//     }


//     for (unsigned int i = 0; i < size; i++) {
//         uint8_t val = ((uint8_t *)buf)[i];
//         for(int str_idx = 0; str_idx < num_strings; str_idx++) {
//             //if (tofind[str_idx][sp.val[str_idx]] == val)
//             //    sp.val[str_idx]++;
//             //else
//             //    sp.val[str_idx] = 0;

//             if (sp.val[str_idx] == strlens[str_idx]) {
//                 // Victory!
//                 printf("%s Match of str %d at: instr_count=%lu :  " TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx "\n",
//                        (is_write ? "WRITE" : "READ"), str_idx, rr_get_guest_instr_count(), p.caller, p.pc, p.cr3);
//                 matches[p].val[str_idx]++;
//                 sp.val[str_idx] = 0;

//                 // Also get the full stack here
//                 CallStack f = {0};
//                 f.n = get_callers(f.callers, n_callers, env);
//                 f.pc = p.pc;
//                 f.asid = p.cr3;
//                 matchstacks[p] = f;


//             }
//         }
//     }


    //######################################################################################################
    //######################################################################################################
    //######################################################################################################
    //######################################################################################################
    //######################################################################################################
    //######################################################################################################
    //######################################################################################################
    //######################################################################################################
    //######################################################################################################
    //######################################################################################################
    // lele: ported from Instruction() from Deadspy
    // Basic: find deadwrite to the position
    // - first: get last access, R W
    // - second: if w-w, report it.

    //######################################################################################################


    // Note: predicated instructions are correctly handled as given in PIN's sample example pinatrace.cpp
    
    /* Comment taken from PIN sample : 
        Instruments memory accesses using a predicated call, i.e.
        the instrumentation is called iff the instruction will actually be executed.
        
        The IA-64 architecture has explicitly predicated instructions.
        On the IA-32 and Intel(R) 64 architectures conditional moves and REP
        prefixed instructions appear as predicated instructions in Pin. */
    
    
    // How may memory operations?
    // lele: no need to do this.
    // UINT32 memOperands = INS_MemoryOperandCount(ins);
    
    // Also get the full stack here
    CallStack callstack = {0};
    callstack.n = get_callers(callstack.callers, n_callers, env);
    printf ("get %d callers\n", callstack.n);
    callstack.pc = p.pc;
    callstack.asid = p.cr3;
    

    // If it is a call/ret instruction, we need to adjust the CCT.
    // ManageCallingContext(ins);
    ManageCallingContext(&callstack); //lele: ported from deadspy, May 6, 2017.
    
    
    uint32_t slot = gCurrentSlot;
    // If it is a memory write then count the number of bytes written 
//#ifndef IP_AND_CCT  
    // //xxx-> IP_AND_CCT uses traces to detect instructions & their write size hence no instruction level counting is needed
    // CHANGE: lele: in PANDA, no trace, so we also use this to count instructions and size. 
    // if(INS_IsMemoryWrite(ins)){
    if(is_write){
        // USIZE writeSize = INS_MemoryWriteSize(ins);
        target_ulong writeSize = size;
        printf("counting written bytes:  " TARGET_FMT_lx "\n", writeSize);
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
    

    // Iterate over each memory operand of the instruction and add Analysis routine to check for dead writes.
    // We correctly handle instructions that do both read and write.
    // lele: no need to ana operands since it's already mem R/W.
    //
    //  - pc as ins address, addr as mem address, buf[0-size-1] as memory content.
    //
    //  - detect deadwrite.

    // for (UINT32 memOp = 0; memOp < memOperands; memOp++) {

        // UINT32 refSize = INS_MemoryOperandSize(ins, memOp);

        target_ulong refSize = size;
        if (! is_write){
            printf("record read (" TARGET_FMT_lx " bytes).\n", size);
        }else{

            printf("record write (" TARGET_FMT_lx " bytes).\n", size);

        // uint32_t slot = gCurrentTrace->nSlots;

            printf("update ipShadow slot when write detected.\n");
            // put next slot in corresponding ins start location;
            target_ulong *ipShadow =  (target_ulong *) gTraceShadowMap[gCurrentContext->address];
            ipShadow[gCurrentSlot] = p.pc;

            gCurrentSlot++;
            gCurrentTrace->nSlots++;


            printf("new slot created for gCurrentContext->address: " TARGET_FMT_lx ", %u (%u)\n", gCurrentContext->address, gCurrentSlot,gCurrentTrace->nSlots);

        	target_ulong * currentTraceShadowIP = (target_ulong *) gTraceShadowMap[gCurrentContext->address];
            printf("set recordedSlots of currentTraceShadowIP[-1] %p to %u\n", currentTraceShadowIP, gCurrentSlot);
            //target_ulong recordedSlots = currentTraceShadowIP[-1]; // 
            currentTraceShadowIP[-1] = gCurrentSlot; // 

        }
        
        switch(refSize){
            case 1:{
                // if (INS_MemoryOperandIsRead(ins, memOp)) {
                    
                if (! is_write) {
                    Record1ByteMemRead((VOID *)p.pc);                        
                }
                else {
                    Record1ByteMemWrite(
#ifdef IP_AND_CCT
                        slot,
#endif
                        (VOID *) p.pc);                    
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
                    Record2ByteMemRead((VOID *)p.pc);                        
                }
                else {
                    Record2ByteMemWrite(
#ifdef IP_AND_CCT
                        slot,
#endif
                        (VOID *) p.pc);                }
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
                    Record4ByteMemRead((VOID *)p.pc);                        
                }
                else {
                    Record4ByteMemWrite(
#ifdef IP_AND_CCT
                        slot,
#endif
                        (VOID *) p.pc);                }
            }
                break;
                
            case 8:{
                       
                if (! is_write) {
                    Record8ByteMemRead((VOID *)p.pc);                        
                }
                else {
                    Record8ByteMemWrite(
#ifdef IP_AND_CCT
                        slot,
#endif
                        (VOID *) p.pc);                }
            }
                break;
                
            case 10:{
                if (! is_write) {
                    Record10ByteMemRead((VOID *)p.pc);                        
                }
                else {
                    Record10ByteMemWrite(
#ifdef IP_AND_CCT
                        slot,
#endif
                        (VOID *) p.pc);                }
               
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
                    Record16ByteMemRead((VOID *)p.pc);                        
                }
                else {
                    Record16ByteMemWrite(
#ifdef IP_AND_CCT
                        slot,
#endif
                        (VOID *) p.pc);                }
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
                    RecordLargeMemRead((void *)p.pc,size);                        
                }
                else {
                    RecordLargeMemWrite(
#ifdef IP_AND_CCT
                        slot,
#endif
                       (VOID *)  p.pc, size);
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
    //gTraceShadowMap.set_empty_key(0);
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
    string statFileName(trace_file_kernel);
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

    //lele: step 1. Sys init

    panda_cb pcb;

    panda_require("callstack_instr");

    //lele: step 2, parse args

    panda_arg_list *args = panda_get_args("trace_deadwrite");

    //step 2.1: args: asid
    const char *arg_str = panda_parse_string_opt(args, "asid", "", "a single asid to search for");
    size_t arg_len = strlen(arg_str);
    if (arg_len > 0) {
        //memcpy(tofind[num_strings], arg_str, arg_len);
        //strlens[num_strings] = arg_len;
        //num_strings++;
    }
    //step 2.2: args: max callers printed
    // n_callers = panda_parse_uint64_opt(args, "callers", 16, "depth of callstack for matches");
    n_callers = CALLERS_PER_INS;
    if (n_callers > MAX_CALLERS) n_callers = MAX_CALLERS;

    //step 2.3: args: log file name prefix
    // deleted, simple hardcoded the prefix


    //lele: init_deadspy: open log file handlers, print first lines

    const char *prefix="trace_deadwrite_test";
    init_deadspy(prefix);

    //lele: step 4: sys int: set callstack plugins, enable precise pc, memcb, and set callback functions.
    if(!init_callstack_instr_api()) return false;

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();
    // Enable memory logging
    panda_enable_memcb();

    pcb.virt_mem_before_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);
    pcb.virt_mem_after_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);


    return true;
}


//#########################################################################
//last STEP: printing
//#########################################################################

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
            if(IsValidIP(curContext->address)){
                fprintf(gTraceFile, "\n! " TARGET_FMT_lx, curContext->address);
                 // Also get the full stack here
                //lele: TODO: get the function name from the curContext->address.
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
                // string fun = PIN_UndecorateSymbolName(RTN_FindNameByAddress(curContext->address),UNDECORATION_COMPLETE);
                // string sub = "memset";
                // if(fun == ".plt"){
                //     if(setjmp(env) == 0) {
                        
                //         if(IsValidPLTSignature(curContext) ) {
                //             target_ulong nextByte = (target_ulong) curContext->address + 2;
                //             int * offset = (int*) nextByte;
                            
                //             target_ulong nextInst = (target_ulong) curContext->address + 6;
                //             ADDRINT loc = *((target_ulong *)(nextInst + *offset));
                //             if(IsValidIP(loc)){
                //                 string s = PIN_UndecorateSymbolName(RTN_FindNameByAddress(loc),UNDECORATION_COMPLETE);
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
                           list<DeadInfoForPresentation> & deadList,
#else // no IP_AND_CCT
                           list<DeadInfo> & deadList,
#endif  // end IP_AND_CCT
                           target_ulong deads){
#ifdef IP_AND_CCT        
        list<DeadInfoForPresentation>::iterator it = deadList.begin();
#else //no IP_AND_CCT        
        list<DeadInfo>::iterator it = deadList.begin();
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
        printf("1: " TARGET_FMT_lx ";2: " TARGET_FMT_lx ";4 " TARGET_FMT_lx ";8: " TARGET_FMT_lx ";10: " TARGET_FMT_lx ";16: " TARGET_FMT_lx ";large: " TARGET_FMT_lx "\n",
          g1ByteWriteInstrCount, g2ByteWriteInstrCount,
          g4ByteWriteInstrCount, g8ByteWriteInstrCount,
          g10ByteWriteInstrCount,g16ByteWriteInstrCount,
          gLargeByteWriteInstrCount);
        target_ulong measurementBaseCount =  g1ByteWriteInstrCount + 2 * g2ByteWriteInstrCount + 4 * g4ByteWriteInstrCount + 8 * g8ByteWriteInstrCount + 10 * g10ByteWriteInstrCount + 16 * g16ByteWriteInstrCount + gLargeByteWriteInstrCount;
#endif  //end MULTI_THREADED
        printf("%s, base count  " TARGET_FMT_lx "\n",__FUNCTION__, measurementBaseCount);
        return measurementBaseCount;        
    }

    // Prints the collected statistics on writes along with their sizes
    inline void PrintEachSizeWrite(){
#ifdef MULTI_THREADED
        fprintf(gTraceFile,"\n1: " TARGET_FMT_lx "",GetTotalNByteWrites(1));
        fprintf(gTraceFile,"\n2: " TARGET_FMT_lx "",GetTotalNByteWrites(2));
        fprintf(gTraceFile,"\n4: " TARGET_FMT_lx "",GetTotalNByteWrites(4));
        fprintf(gTraceFile,"\n8: " TARGET_FMT_lx "",GetTotalNByteWrites(8));
        fprintf(gTraceFile,"\n10: " TARGET_FMT_lx "",GetTotalNByteWrites(10));
        fprintf(gTraceFile,"\n16: " TARGET_FMT_lx "",GetTotalNByteWrites(16));
        fprintf(gTraceFile,"\nother: " TARGET_FMT_lx "",GetTotalNByteWrites(-1));
        
#else  //no MULTI_THREADED        
        fprintf(gTraceFile,"\n1: " TARGET_FMT_lx "",g1ByteWriteInstrCount);
        fprintf(gTraceFile,"\n2: " TARGET_FMT_lx "",g2ByteWriteInstrCount);
        fprintf(gTraceFile,"\n4: " TARGET_FMT_lx "",g4ByteWriteInstrCount);
        fprintf(gTraceFile,"\n8: " TARGET_FMT_lx "",g8ByteWriteInstrCount);
        fprintf(gTraceFile,"\n10: " TARGET_FMT_lx "",g10ByteWriteInstrCount);
        fprintf(gTraceFile,"\n16: " TARGET_FMT_lx "",g16ByteWriteInstrCount);
        fprintf(gTraceFile,"\nother: " TARGET_FMT_lx "",gLargeByteWriteInstrCount);
#endif //end MULTI_THREADED
    }
    
#ifdef IP_AND_CCT  
    // Given a pointer (i.e. slot) within a trace node, returns the IP corresponding to that slot
    // Lele: Given a pointer TODO: 
    //  within a trace node, returns the IP corresponding to that slot
    //inline ADDRINT GetIPFromInfo(void * ptr){
    inline ADDRINT GetIPFromInfo(void * ptr){
        //lele: use ContextNode->address as key instead of TraceNode
		TraceNode * traceNode = *((TraceNode **) ptr);
        // ContextNode * contextNode = (ContextNode *) ptr;
        
		// what is my slot id ?
		uint32_t slotNo = 0;
		for( ; slotNo < traceNode->nSlots; slotNo++){
		// for( ; slotNo < contextNode->nSlots; slotNo++){
			if (&traceNode->childIPs[slotNo] == (TraceNode **) ptr)
				break;
		}
        
		ADDRINT *ip = (ADDRINT *) gTraceShadowMap[traceNode->address] ;
		return ip[slotNo];
	}
    
    void  panda_GetSourceLocation(ADDRINT ip,int32_t *line, string *file){
        //Lele: given IP, return the line number and file
        *line = 0;
        *file = "---file_info_not_implemented---";
    }

    // Given a pointer (i.e. slot) within a trace node, returns the Line number corresponding to that slot
	inline string GetLineFromInfo(void * ptr){
		ADDRINT ip = GetIPFromInfo(ptr);
        string file;
        int32_t line;
        //PIN_GetSourceLocation(ip, NULL, &line,&file);
        panda_GetSourceLocation(ip, &line,&file);
		std::ostringstream retVal;
		retVal << line;
		return file + ":" + retVal.str();
    }    
    
    
    
    // Prints the complete calling context including the line nunbers and the context's contribution, given a DeadInfo 
    inline VOID PrintIPAndCallingContexts(const DeadInfoForPresentation & di, target_ulong measurementBaseCount){
        
        fprintf(gTraceFile,"\n " TARGET_FMT_lx " = %e",di.count, di.count * 100.0 / measurementBaseCount);
        fprintf(gTraceFile,"\n-------------------------------------------------------\n");
#ifdef MERGE_SAME_LINES
        fprintf(gTraceFile,"\n%s",di.pMergedDeadInfo->line1.c_str());                                    
#else // no MERGE_SAME_LINES
        string file;
        int32_t line;
        panda_GetSourceLocation( di.pMergedDeadInfo->ip1,  &line,&file);
        fprintf(gTraceFile,"\n%p:%s:%u",(void *)(di.pMergedDeadInfo->ip1),file.c_str(),line);                                    
#endif //end MERGE_SAME_LINES        
        PrintFullCallingContext(di.pMergedDeadInfo->context1);
        fprintf(gTraceFile,"\n***********************\n");
#ifdef MERGE_SAME_LINES
        fprintf(gTraceFile,"\n%s",di.pMergedDeadInfo->line2.c_str());                                    
#else //no MERGE_SAME_LINES        
        panda_GetSourceLocation( di.pMergedDeadInfo->ip2,  &line,&file);
        fprintf(gTraceFile,"\n%p:%s:%u",(void *)(di.pMergedDeadInfo->ip2),file.c_str(),line);
#endif //end MERGE_SAME_LINES        
        PrintFullCallingContext(di.pMergedDeadInfo->context2);
        fprintf(gTraceFile,"\n-------------------------------------------------------\n");
    }
    
    
    
    // On each Unload of a loaded image, the accummulated deadness information is dumped
    VOID ImageUnload() {
        printf("\nUnloading");
        // Update gTotalInstCount first 
        target_ulong measurementBaseCount =  GetMeasurementBaseCount(); 
        
        fprintf(gTraceFile, "\nTotal Instr =  " TARGET_FMT_lx "", measurementBaseCount);
        printf("total instr:  " TARGET_FMT_lx "\n", measurementBaseCount);
        fflush(gTraceFile);
        
#if defined(CONTINUOUS_DEADINFO)
        //sparse_hash_map<uint64_t, uint64_t>::iterator mapIt = DeadMap.begin();
        unordered_map<uint64_t, uint64_t>::iterator mapIt = DeadMap.begin();
        //dense_hash_map<uint64_t, uint64_t>::iterator mapIt = DeadMap.begin();
#else //no defined(CONTINUOUS_DEADINFO)        
        dense_hash_map<uint64_t, DeadInfo>::iterator mapIt = DeadMap.begin();
        //unordered_map<uint64_t, DeadInfo>::iterator mapIt = DeadMap.begin();
#endif //end defined(CONTINUOUS_DEADINFO)        
        map<MergedDeadInfo,uint64_t> mergedDeadInfoMap;
        
        printf("%s: get Header of the DeadMap: %lu \n",__FUNCTION__,mapIt->first);
#if defined(CONTINUOUS_DEADINFO)
        printf("%s: continuous\n", __FUNCTION__);
        for (; mapIt != DeadMap.end(); mapIt++) {
            MergedDeadInfo tmpMergedDeadInfo;
            uint64_t hash = mapIt->first;
            TraceNode ** ctxt1 = (TraceNode **)(gPreAllocatedContextBuffer + (hash >> 32));
            TraceNode ** ctxt2 = (TraceNode **)(gPreAllocatedContextBuffer + (hash & 0xffffffff));
            
            tmpMergedDeadInfo.context1 = (*ctxt1)->parent;
            tmpMergedDeadInfo.context2 = (*ctxt2)->parent;
#ifdef MERGE_SAME_LINES
            tmpMergedDeadInfo.line1 = GetLineFromInfo(ctxt1);
            tmpMergedDeadInfo.line2 = GetLineFromInfo(ctxt2);
#else  //no MERGE_SAME_LINES            
            tmpMergedDeadInfo.ip1 = GetIPFromInfo(ctxt1);
            tmpMergedDeadInfo.ip2 = GetIPFromInfo(ctxt2);
#endif //end MERGE_SAME_LINES            
            map<MergedDeadInfo,uint64_t>::iterator tmpIt;
            if( (tmpIt = mergedDeadInfoMap.find(tmpMergedDeadInfo)) == mergedDeadInfoMap.end()) {
                mergedDeadInfoMap[tmpMergedDeadInfo] = mapIt->second;
            } else {
                
                tmpIt->second  += mapIt->second;
            }
        }
        
	    // clear dead map now
        DeadMap.clear();
        
        
#else   // no defined(CONTINUOUS_DEADINFO)        

        printf("%s: NOT continuous\n", __FUNCTION__);
        for (; mapIt != DeadMap.end(); mapIt++) {
            MergedDeadInfo tmpMergedDeadInfo;
            printf("counting written bytes:  " TARGET_FMT_lx "\n", writeSize);
            tmpMergedDeadInfo.context1 = (*((TraceNode **)((mapIt->second).firstIP)))->parent;
            tmpMergedDeadInfo.context2 = (*((TraceNode **)((mapIt->second).secondIP)))->parent;
#ifdef MERGE_SAME_LINES
            tmpMergedDeadInfo.line1 = GetLineFromInfo(mapIt->second.firstIP);
            tmpMergedDeadInfo.line2 = GetLineFromInfo(mapIt->second.secondIP);
#else //no MERGE_SAME_LINES            
            tmpMergedDeadInfo.ip1 = GetIPFromInfo(mapIt->second.firstIP);
            tmpMergedDeadInfo.ip2 = GetIPFromInfo(mapIt->second.secondIP);
#endif //end MERGE_SAME_LINES            
            map<MergedDeadInfo,uint64_t>::iterator tmpIt;
            if( (tmpIt = mergedDeadInfoMap.find(tmpMergedDeadInfo)) == mergedDeadInfoMap.end()) {
                mergedDeadInfoMap[tmpMergedDeadInfo] = mapIt->second.count;
            } else {
                
                tmpIt->second  += mapIt->second.count;
            }
        }
        
	    // clear dead map now
        DeadMap.clear();
#endif  // end defined(CONTINUOUS_DEADINFO)        
        
        map<MergedDeadInfo,uint64_t>::iterator it = mergedDeadInfoMap.begin();	
        list<DeadInfoForPresentation> deadList;
        for (; it != mergedDeadInfoMap.end(); it ++) {
            DeadInfoForPresentation deadInfoForPresentation;
            deadInfoForPresentation.pMergedDeadInfo = &(it->first);
            deadInfoForPresentation.count = it->second;
            deadList.push_back(deadInfoForPresentation);
        }
        deadList.sort(MergedDeadInfoComparer);
        
	    //present and delete all
        
        list<DeadInfoForPresentation>::iterator dipIter = deadList.begin();
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
                fprintf(gTraceFile,"\nCTXT_DEAD_CNT: " TARGET_FMT_lx " = %e",dipIter->count, dipIter->count * 100.0 / measurementBaseCount);
#endif                //end PRINT_ALL_CTXT
            }
            
            gTotalDead += dipIter->count ;
            deads++;
        }
        
        
        PrintEachSizeWrite();
        
#ifdef TESTING_BYTES
        PrintInstructionBreakdown();
#endif //end TESTING_BYTES        
        
#ifdef GATHER_STATS
        PrintStats(deadList, deads);
#endif //end GATHER_STATS        
        
        mergedDeadInfoMap.clear();
        deadList.clear();
        //PIN_UnlockClient();
	}
    
#else //no IP_AND_CCT
    // On each Unload of a loaded image, the accummulated deadness information is dumped (JUST the CCT case, no IP)
    VOID ImageUnload() {
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
        fprintf(gTraceFile, "\nTotal Instr =  " TARGET_FMT_lx "", measurementBaseCount);
        printf("get total Instr:  " TARGET_FMT_lx "\n", measurementBaseCount);
        fflush(gTraceFile);
        
#if defined(CONTINUOUS_DEADINFO)
        unordered_map<uint64_t, uint64_t>::iterator mapIt;
        //dense_hash_map<uint64_t, uint64_t>::iterator mapIt;
        //sparse_hash_map<uint64_t, uint64_t>::iterator mapIt;
#else // no defined(CONTINUOUS_DEADINFO)        
        dense_hash_map<uint64_t, DeadInfo>::iterator mapIt;
        //unordered_map<uint64_t, DeadInfo>::iterator mapIt;
#endif  //end defined(CONTINUOUS_DEADINFO)        
        list<DeadInfo> deadList;
        
        
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
        list<DeadInfo>::iterator it = deadList.begin();
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
                    fprintf(gTraceFile,"\n " TARGET_FMT_lx " = %e",it->count, it->count * 100.0 / measurementBaseCount);
                    PrintCallingContexts(*it);
                } catch (...) {
                    fprintf(gTraceFile,"\nexcept");
                }
            } else {
#ifdef PRINT_ALL_CTXT
                // print only dead count
                fprintf(gTraceFile,"\nCTXT_DEAD_CNT: " TARGET_FMT_lx " = %e",it->count, it->count * 100.0 / measurementBaseCount);
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
    fprintf(gTraceFile, "\nGrandTotalWrites =  " TARGET_FMT_lx "",measurementBaseCount);
    fprintf(gTraceFile, "\nGrandTotalDead =  " TARGET_FMT_lx " = %e%%",gTotalDead, gTotalDead * 100.0 / measurementBaseCount);
#ifdef MULTI_THREADED        
    fprintf(gTraceFile, "\nGrandTotalMTDead =  " TARGET_FMT_lx " = %e%%",gTotalMTDead, gTotalMTDead * 100.0 / measurementBaseCount);
#endif // end MULTI_THREADED        
    fprintf(gTraceFile, "\n#eof");
    fclose(gTraceFile);
}

void report_deadspy(void * self){
    //lele: ported from deadspy: ImageUnload and Fini
    // 
    printf("%s: ImageUnload()\n", __FUNCTION__);
    ImageUnload(); //lele: necessary?
    //
    printf("%s: Fini()\n", __FUNCTION__);
    Fini();
}

void uninit_plugin(void *self) {

    printf("%s: report deadspy\n", __FUNCTION__);
    report_deadspy(self);

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

// done last step: printing

//#########################


//#endif //defined(TARGET_I386)