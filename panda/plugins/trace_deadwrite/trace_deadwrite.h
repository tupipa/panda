

#ifndef __TRACE_DEADWRITE_H_
#define __TRACE_DEADWRITE_H_

// This needs to be defined before anything is included in order to get
// the PRIx64 macro

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
#include <unordered_set>
#include <set>
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
#include <fstream>
#include <algorithm>
// Need GOOGLE sparse hash tables
#include <google/sparse_hash_map>
#include <google/dense_hash_map>
using google::sparse_hash_map;      // namespace where class lives by default
using google::dense_hash_map;      // namespace where class lives by default

#include <capstone/capstone.h>
#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#elif defined(TARGET_PPC)
#include <capstone/ppc.h>
#endif


extern "C" {
#include "panda/plugin.h"
#include "panda/plugin_plugin.h"


// #include "trace_mem.h"
// #include "trace_deadwrite.h"

#include "panda/rr/rr_log.h"
#include "panda/addr.h"
#include "panda/plog.h"

// #include "pri/pri_types.h"
// #include "pri/pri_ext.h"
// #include "pri/pri.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "osi_linux/osi_linux_ext.h"

// #include "pri_dwarf/pri_dwarf_types.h"
// #include "pri_dwarf/pri_dwarf_ext.h"

#include "asidstory/asidstory.h"
// #include "asidstory/asidstory_ext.h"


    bool init_plugin(void *);
    void uninit_plugin(void *);

    // void init_deadspy();
    // int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
    // int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);


    // int before_block_exec(CPUState *cpu, TranslationBlock *tb) ;

    // int after_block_exec(CPUState *cpu, TranslationBlock *tb) ;

    // int handle_asid_change(CPUState *cpu, target_ulong old_asid, target_ulong new_asid);
    
    // prototype for the register-this-callback fn
    //PPP_PROT_REG_CB(on_ssm);
    //PPP_PROT_REG_CB(on_deadwrite);

    // int get_loglevel() ;
    // void set_loglevel(int new_loglevel);

    // void on_line_change(CPUState *cpu, target_ulong pc, const char *file_Name, const char *funct_name, unsigned long long lno);
}

#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

#include "util/runcmd.h"
// #include "util/struct_hash.h"

// using namespace __gnu_cxx;

// using namespace std;
// using namespace std::tr1;



// ######################################################
// ######################################################
// ########## Part 1.0: Macros Definitions ##############
// ######################################################
// ######################################################



#define MAX_STRINGS 100
#define MAX_CALLERS 128

#define CALLERS_PER_INS 3
#define CALLERS_LAST 0
#define CALLERS_SECOND_LAST 1
#define CALLERS_THIRD_LAST 2

#define MAX_STRLEN  1024





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
#define SRC_FILE_NA "debug_info_not_available"
#define CONTEXT_TREE_VECTOR_SIZE (10)
#define MAX_CCT_PRINT_DEPTH (900)
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
#define CUR_CTXT (&gCurrentTraceIpVector[slot])
//#define CUR_CTXT (gCurrentContext)
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
}while(0)

//printf("%s:continuous: report one dead (&gCurrentTraceIpVector[%d]:%p, %p, %d, hash :0x%lx)\n", 
    //   __FUNCTION__, slot, curCtxt,lastCtxt, size, hashVar);

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

//printf("%s: no-continuous, report one dead (%p, %p, %d)\n", 
    //   __FUNCTION__, curCtxt,lastCtxt, size); 

#endif // end defined(CONTINUOUS_DEADINFO)

#define REPORT_IF_DEAD(mask, curCtxt, lastCtxt, hashVar) do {if (state & (mask)){ \
REPORT_DEAD(curCtxt, lastCtxt,hashVar, 1);\
}}while(0)

//printf("\t dead mask: %p\n", (void*)(uintptr_t)mask);


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

// ######################################
// test flag used to control running time.

//target_ulong testTotal = 0x100000;	 // number of mem_callback operations for target program
bool gIsTest;	// use to enable or disable test.
target_ulong testTotal = 0;	 // if test enabled, this is the number of mem_callback operations for target program


// ######################################################
// ######################################################
// ########## Part 1.1: Variable/Struct Definitions #####
// ######################################################
// ######################################################

//###########################
// BEGAIN: capstone related BB disas

enum ins_type {
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


csh csh_hd_32;
csh csh_hd_64;

bool init_capstone_done = false;
// Track the different stacks we have seen to handle multiple threads
// within a single process.
// std::map<target_ulong,std::set<target_ulong>> stacks_seen;

// Borrowed from trace_insthist
//
// csh handle;
// cs_insn *insn;

// target_ulong asid;
// PC => number of instructions in the TB
// std::tr1::unordered_map<target_ulong,int> tb_insns_count;
// std::tr1::unordered_map<target_ulong,cs_insn *> tb_insns;

std::tr1::unordered_map<target_ulong, ins_type> block_cache;  //

// END: done capstone related BB disas.
//##################################################

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
struct BlockNode;
struct DeadInfoForPresentation;
inline ADDRINT GetIPFromInfo(void * ptr);
inline std::string GetLineFromInfo(void * ptr);
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
    sparse_hash_map<ADDRINT,BlockNode *> childBlocks;
    // BlockNode * childTrace;
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
struct FileLineInfo{
    bool valid; // set to valid if FileLineInfo is stored in it.
    std::string fileName;
    std::string funName;
    unsigned long lineNum;
    std::string extraInfo;

	bool operator==(const FileLineInfo  & x) const{
		if ( valid && x.valid && this->fileName == x.fileName && this->lineNum == x.lineNum)
            return true;
		return false;
	}
};

struct MergedDeadInfo{
	ContextNode * context1;
	ContextNode * context2;
#ifdef MERGE_SAME_LINES
	std::string line1;
	std::string line2;
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

struct BlockNode{
    ContextNode * parent;
    BlockNode ** childIPs;
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

//std::map < void *, Status > MemState;
#if defined(CONTINUOUS_DEADINFO)
//hash_map<uint64_t, uint64_t> DeadMap;
//hash_map<uint64_t, uint64_t>::iterator gDeadMapIt;
std::tr1::unordered_map<uint64_t, uint64_t> DeadMap;
std::tr1::unordered_map<uint64_t, uint64_t>::iterator gDeadMapIt;

#endif // end defined(CONTINUOUS_DEADINFO)



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
std::vector<ContextTree> gContextTreeVector;
#endif //end MULTI_THREADED

// use asid, pid, ppid to distinguish proces
// use proc->name only for assistance.
struct DebugFile{
    bool isKernel;
    std::string filename;
    target_ulong offset;
    target_ulong size;

	bool operator==(const DebugFile  & x) const{ 
		if ( this->filename == x.filename && this->offset == x.offset && this->size == x.size){
            return true;
        }
		return false; 
	}

	bool operator<(const DebugFile  & x) const{
		if (this->offset < x.offset){
            // different asid, compare according to asid.
            return true;
        }
        return false;
	}
};

struct KernelSym{
    target_ulong address;
    std::string type;
    std::string function;
    std::string module_name;

	bool operator==(const KernelSym  & x) const{ 
		if ( this->address == x.address && this->type == x.type && this->function == x.function){
            return true;
        }
		return false; 
	}

	bool operator<(const KernelSym  & x) const{
		if (this->address < x.address){
            // different asid, compare according to asid.
            return true;
        }
        return false;
	}
};

// use asid, pid, ppid to distinguish proces
// use proc->name only for assistance.
struct ProcID{

    OsiProc *proc;

	bool operator==(const ProcID  & x) const{
		// if ( this->proc->asid == (x.proc)->asid && std::string(this->proc->name) == std::string((x.proc)->name)){
        //     return true;
        // }
        // printf("%s, %s, %p != %s, %p\n", __FUNCTION__, (x.proc)->name, (void *)(uintptr_t)x.proc->asid,this->proc->name, (void *)(uintptr_t) this->proc->asid);
        // exit(-1);
		// return false;
        
		if ( this->proc->asid == (x.proc)->asid && this->proc->pid == (x.proc)->pid && this->proc->ppid == (x.proc)->ppid){
            return true;
        }

        // printf("%s, %s: (0x" TARGET_FMT_lx "," TARGET_FMT_lu "," TARGET_FMT_lu 
        //         ")\n\t != %s (0x" TARGET_FMT_lx "," TARGET_FMT_lu "," TARGET_FMT_lu
        //         ")\n",
        //  __FUNCTION__, 
        //  (x.proc)->name, x.proc->asid, x.proc->pid, x.proc->ppid,
        //  this->proc->name, this->proc->asid, this->proc->pid, this->proc->ppid);

        // exit(-1);
		return false;
        
	}

	bool operator<(const ProcID  & x) const{

		if (this->proc->asid == x.proc->asid){
            // same asid, then compare name.
            if (this->proc->name && x.proc->name){
                std::string name1(this->proc->name);
                std::string name2(x.proc->name);
                if (name1.compare(name2) < 0){
                    return true;
                }else{
                    return false;
                }
            }
        }else if (this->proc->asid < x.proc->asid){
            // different asid, compare according to asid.
            return true;
        }
        return false;
	}
};


// use base, offset, size to distinguish proces lib/kernel module
// use m->name only for assistance.
struct ModuleID{

    //OsiModule *m;

    target_ulong base;
    target_ulong offset;
    target_ulong size;
    std::string name;
    std::string file;
    bool is_valid;

    ModuleID(OsiModule *m){
        this->base = m->base;
        this->offset = m->offset;
        this->size = m->size;

        if(m->name != NULL)
            this->name = std::string(m->name);
        else
            this->name = "";
        
        if (this->name == "" || this->name == "[???]" || this->name == "???"){
        	is_valid=false;
        }else{
        	is_valid=true;
        }

        if(m->file == NULL)
            this->file="";
        else 
            this->file = std::string(m->file);
    }

	bool operator==(const ModuleID  & x) const{

		if ( this->base == x.base && this->offset == x.offset && this->size == x.size){
            return true;
        }
        
        return false;
        
	}

	bool operator<(const ModuleID  & x) const{
		if (this->base < x.base )
            return true;
		return false;
	}
};


namespace std {

  template <>
  struct hash<ProcID>
  {
    std::size_t operator()(const ProcID& k) const
    {
      using std::size_t;
      using std::hash;
      using std::string;

      // Compute individual hash values for first,
      // second and third and combine them using XOR
      // and bit shifting:

      return (hash<string>()(std::string(k.proc->name))
               ^ (hash<target_ulong>()(k.proc->asid) << 1));
    }
  };

}


#ifdef IP_AND_CCT
sparse_hash_map<ADDRINT, BlockNode *>::iterator gTraceIter;
//dense_hash_map<ADDRINT, void *> gBlockShadowMap;
// hash_map<ADDRINT, void *> gBlockShadowMap;
//Lele: we don't use StartAddr of a trace as key, instead, we use ContextNode's address as key, to store an array, doing the same thing: ---mapping the slots index of each write instruction in a function to its corresponding IP. In order to be compatible with the legacy BlockNode, we use one tracenode to store the array, with StartAddr equal to the ContextNodes' address.
std::tr1::unordered_map<ADDRINT, void *> gBlockShadowMap;
ADDRINT * gTmpBlockIpShadow;

std::tr1::unordered_map<ADDRINT, bool> gBlockShadowMapDone;
std::tr1::unordered_map<ADDRINT, std::tr1::unordered_map<ADDRINT, int> *> gBlockShadowIPtoSlot;
std::tr1::unordered_map<ADDRINT, std::tr1::unordered_map<ADDRINT, FileLineInfo *> *> gAsidPCtoFileLine;

std::string gProcToMonitor;

// gProcFoundByProcChange:  in handle_proc_change, set to true when found the target, to false otherwise. 
//  this will be used in other places to check the consistent. like in is_target_process_running.
//  e.g. there will be inconsistent if gProcFoundByProcChange is false, but is_target_proc_running return true.
bool gProcFoundByProcChange;

// flag used only for is_target_process_running.
// once target is found, set this flag until whole program exits;
// - 
bool gProcFound=false;

//store all debug file paths
//std::vector<std::string> gDebugFiles;

std::vector<DebugFile> gDebugFiles;
//store all process names
std::vector<std::string> gProcs;

// used to store all procs with diff pid/ppid/asid combinations.
std::vector<ProcID> gProcIDs;

// used to store all modules, to be deprecated. not so usefull?
std::vector<ModuleID> gModuleIDs;
// std::vector<ProcID> gProcStructs;


// std::tr1::unordered_map<target_ulong, OsiProc> gRunningProcs;
// can be used to store all procs, name/pid/ppid/asid diffs.
// std::unordered_set<ProcID> gRunningProcs;
std::set<ProcID> gRunningProcs;

//indicate whether we ever searched the debug file for a proc name, we use this to search only once for each proc name.
std::tr1::unordered_map<std::string, bool> gProcToDebugDone;
//store a map from proc name to its debug file.
std::tr1::unordered_map<std::string, int> gProcToDebugFileIndex;
//store a map from debug file to its proc name.
std::tr1::unordered_map<std::string, int> gDebugFiletoProcIndex;

//store map from asid to proc name index.
std::tr1::unordered_map<target_ulong, int> gAsidToProcIndex;

//store currentTargetDebugPath, this should be the same as gDebugFiles[gProcToDebugFileIndex[gProcToMonitor]]
std::string gCurrentTargetDebugFile;

// System map, mapping kernel address to function names.
// values read from /boot/System.map-(uname -r), or from /proc/kallsyms
std::map<target_ulong, KernelSym> gSysMap;


// gCurrentFuncBlock and gFuncChanged 
// gCurrentFuncBlock used to track the first block of the current func
// gFuncChanged used to track 
// TranslationBlock *gCurrentFuncBlock;
// bool gFuncChanged;

// tracking call stack dynamically
// stackid -> shadow stack
std::map<target_ulong, std::vector<target_ulong>> gCallStacks;
// stackid -> function entry points
std::map<target_ulong, std::vector<target_ulong>> gFunctionStacks;


BlockNode * gCurrentTraceBlock;
uint32_t gCurrentSlot;

bool gInitiatedCall = false;
bool gInitiatedRet = false;
bool gInitiatedINT = false;
bool gInitiatedIRET = false;
bool gNewBasicBlock = false; // tracking new Basic Blocks in gShadowMap, and used to update childIPs during mem_callback execution.
bool gNewBlockNode = false; // tracking new BlockNode in CCT, and used to update childIPs during mem_callback execution.
BlockNode ** gCurrentTraceIpVector;
ADDRINT gCurrentCallerIp;

bool gTraceKernel=false; //trace all kernel processes; asid=0
bool gTraceApp=false; // trace all other asids !=0;
bool gTraceOne = false; //trace only one given ASID, kernel=0, or other asids. If this is true, the 'traceKernel' and 'traceApp' is invalide; If ASID not given, default is 0.

// should be deprecated, use gTargetPID and gTargetPPID instead.
ADDRINT gTargetAsid=0x0; //target ASID;
ADDRINT gTargetAsid_struct=0x0; //target ASID;

target_ulong gTargetPID=0xfffff; //target pid;
target_ulong gTargetPPID=0xffff; //target ppid;
bool gTargetIsKernelMod;

ProcID gTargetProcID;   //target proc by ProcID;

bool gIsTargetBlock = false; // used to tracking whether in a block for target process. will be set/reset in before_block_exe and after_block_exe.
//ADDRINT gTargetASID=0x0; //target ASID;

// gIgnoredASIDs < asid1, asid2, .. >:
//  - store ignored asids, as well as the basic block of this asid's last occurance.
std::unordered_set<target_ulong> gIgnoredASIDs;


uint32_t gContextTreeIndex;

struct ContextTree{
    ContextNode * rootContext;
    ContextNode * currentContext;
};
std::vector<ContextTree> gContextTreeVector;

VOID GoDownCallChain(ADDRINT){}
VOID GoDownCallChain(CPUState *cpu, TranslationBlock *tb);
VOID UpdateDataOnFunctionEntry(ADDRINT currentIp){}
VOID UpdateDataOnFunctionEntry(CPUState *cpu, TranslationBlock *tb);
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
// int n_callers = 16;



// ######################################################
// ######################################################
// ########## Part 1.2: Function Declarations ###########
// ######################################################
// ######################################################

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
// extern "C" {

// bool init_plugin(void *);
// void init_deadspy();
// void uninit_plugin(void *);
// int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
// int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

// // prototype for the register-this-callback fn
// //PPP_PROT_REG_CB(on_ssm);
// //PPP_PROT_REG_CB(on_deadwrite);

// }

inline bool MergedDeadInfoComparer(const DeadInfoForPresentation & first, const DeadInfoForPresentation  &second);
inline bool DeadInfoComparer(const DeadInfo &first, const DeadInfo &second);
inline bool IsValidIP(ADDRINT ip);
inline bool IsValidIP(DeadInfo  di);


void report_deadspy();

void printAllProcsFound();

void init_deadspy();

extern "C"{

    int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
    int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);


    int before_block_exec(CPUState *cpu, TranslationBlock *tb) ;

    int after_block_exec(CPUState *cpu, TranslationBlock *tb) ;

    int handle_asid_change(CPUState *cpu, target_ulong old_asid, target_ulong new_asid);


    int handle_proc_change(CPUState *cpu, target_ulong old_asid, target_ulong new_asid);

}

target_ulong panda_current_asid_proc_struct(CPUState *cpu);

OsiProc * get_current_running_process(CPUState *cpu);

inline bool is_target_process_running(CPUState *cpu);

inline void print_proc_info(const OsiProc *proc);

inline void print_mod_info(const OsiModule *mod);

inline void printRunningProcs();

int checkNewProc(std::string procName);

int checkNewProcID(const ProcID & proc);

void  panda_GetSourceLocation(ADDRINT ip, unsigned long *line, std::string *file, std::string *func);

// the type for the ppp callback fn that can be passed to string search to be called
// whenever a string match is observed
typedef void (* on_deadwrite_t)(CPUState *env, target_ulong pc, target_ulong addr,
			  uint8_t *matched_string, uint32_t matched_string_lenght, 
			  bool is_write);


#endif
