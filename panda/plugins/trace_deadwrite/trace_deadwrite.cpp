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


        -- 
TODO:
    - data structure for state(M) and context(M) as in deadspy paper.
        state(M): 'R'/'W'
        context(M): *prog_point?

    
    - report method once a deadwrite is found.

    - use shadow memory with state(M) and context(M), as in deadspy paper.

 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
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
#include <sys/types.h>

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

using namespace std;
using namespace std::tr1;

//lele: make it comparable for the legacy codes from deadspy.cpp in PIN
#define ADDRINT target_ulong
#define VOID void

#define CONTINUOUS_DEADINFO
#define IP_AND_CCT

//#define IP_AND_CCT
//#define MERGE_SAME_LINES	
//#define TESTING_BYTES
//#define GATHER_STATS
//MT
//#define MULTI_THREADED

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

#define LEVEL_1_PAGE_TABLE_SLOT(addr) ((((uint64_t)addr) >> (LEVEL_2_PAGE_TABLE_BITS + PAGE_OFFSET_BITS)) & 0xfffff)
#define LEVEL_2_PAGE_TABLE_SLOT(addr) ((((uint64_t)addr) >> (PAGE_OFFSET_BITS)) & 0xFFF)


// have R, W representative macros
#define READ_ACTION (0) 
#define WRITE_ACTION (0xff) 

#define ONE_BYTE_READ_ACTION (0)
#define TWO_BYTE_READ_ACTION (0)
#define FOUR_BYTE_READ_ACTION (0)
#define EIGHT_BYTE_READ_ACTION (0)

#define ONE_BYTE_WRITE_ACTION (0xff)
#define TWO_BYTE_WRITE_ACTION (0xffff)
#define FOUR_BYTE_WRITE_ACTION (0xffffffff)
#define EIGHT_BYTE_WRITE_ACTION (0xffffffffffffffff)



// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

// prototype for the register-this-callback fn
//PPP_PROT_REG_CB(on_ssm);
//PPP_PROT_REG_CB(on_deadwrite);

}



struct ContextNode;
struct DeadInfo;


FILE *gTraceFile;

#ifdef IP_AND_CCT
struct MergedDeadInfo;
struct TraceNode;
struct DeadInfoForPresentation;
inline ADDRINT GetIPFromInfo(void * ptr);
inline string GetLineFromInfo(void * ptr);
#endif // end IP_AND_CCT

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
    uint64_t count;
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
	uint64_t count;
};

inline bool MergedDeadInfoComparer(const DeadInfoForPresentation & first, const DeadInfoForPresentation  &second);
inline bool DeadInfoComparer(const DeadInfo &first, const DeadInfo &second);
inline bool IsValidIP(ADDRINT ip);
inline bool IsValidIP(DeadInfo  di);

//map < void *, Status > MemState;
#if defined(CONTINUOUS_DEADINFO)
//hash_map<uint64_t, uint64_t> DeadMap;
//hash_map<uint64_t, uint64_t>::iterator gDeadMapIt;
unordered_map<uint64_t, uint64_t> DeadMap;
unordered_map<uint64_t, uint64_t>::iterator gDeadMapIt;

#define DECLARE_HASHVAR(name) uint64_t name

#define REPORT_DEAD(curCtxt, lastCtxt,hashVar, size) do { \
CONTEXT_HASH_128BITS_TO_64BITS(curCtxt, lastCtxt,hashVar)  \
if ( (gDeadMapIt = DeadMap.find(hashVar))  == DeadMap.end()) {    \
DeadMap.insert(std::pair<uint64_t, uint64_t>(hashVar,size)); \
} else {    \
(gDeadMapIt->second) += size;    \
}   \
}while(0)

#endif

#ifdef CONTINUOUS_DEADINFO
//#define PRE_ALLOCATED_BUFFER_SIZE (1L << 35)
// default use this
#define PRE_ALLOCATED_BUFFER_SIZE (1L << 32)
void ** gPreAllocatedContextBuffer;
uint64_t gCurPreAllocatedContextBufferIndex;
#endif //end CONTINUOUS_DEADINFO


struct ContextNode {
    ContextNode * parent;
    sparse_hash_map<ADDRINT,ContextNode *> childContexts;
#ifdef IP_AND_CCT
    sparse_hash_map<ADDRINT,TraceNode *> childTraces;
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


inline bool MergedDeadInfoComparer(const DeadInfoForPresentation & first, const DeadInfoForPresentation  &second) {
    return first.count > second.count ? true : false;
}

inline bool DeadInfoComparer(const DeadInfo &first, const DeadInfo &second) {
    return first.count > second.count ? true : false;
}


// Returns true if the given address belongs to one of the loaded binaries
inline bool IsValidIP(ADDRINT ip){
    // for( IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img) ){
    //     if(ip >= IMG_LowAddress(img) && ip <= IMG_HighAddress(img)){
    //         return true;
    //     }
    // }
    // return false;
    return true;
}

// Returns true if the given deadinfo belongs to one of the loaded binaries
inline bool IsValidIP(DeadInfo  di){
    // bool res = false;
    // for( IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img) ){
    //     if((ADDRINT)di.firstIP >= IMG_LowAddress(img) && (ADDRINT)di.firstIP <= IMG_HighAddress(img)){
    //         res = true;
    //         break;	
    //     }
    // }
    // if(!res)
    //     return false;
    // for( IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img) ){
    //     if((ADDRINT)di.secondIP >= IMG_LowAddress(img) && (ADDRINT)di.secondIP <= IMG_HighAddress(img)){  
    //         return true;
    //     }
    // }
    // return false;
    return true;
}

  // Prints the complete calling context including the line nunbers and the context's contribution, given a DeadInfo 
    inline VOID PrintIPAndCallingContexts(const DeadInfoForPresentation & di, uint64_t measurementBaseCount){
        
        fprintf(gTraceFile,"\n%lu = %e",di.count, di.count * 100.0 / measurementBaseCount);
        fprintf(gTraceFile,"\n-------------------------------------------------------\n");
#ifdef MERGE_SAME_LINES
        fprintf(gTraceFile,"\n%s",di.pMergedDeadInfo->line1.c_str());                                    
#else // no MERGE_SAME_LINES
        string file;
        INT32 line;
        PIN_GetSourceLocation( di.pMergedDeadInfo->ip1, NULL, &line,&file);
        fprintf(gTraceFile,"\n%p:%s:%d",(void *)(di.pMergedDeadInfo->ip1),file.c_str(),line);                                    
#endif //end MERGE_SAME_LINES        
        PrintFullCallingContext(di.pMergedDeadInfo->context1);
        fprintf(gTraceFile,"\n***********************\n");
#ifdef MERGE_SAME_LINES
        fprintf(gTraceFile,"\n%s",di.pMergedDeadInfo->line2.c_str());                                    
#else //no MERGE_SAME_LINES        
        PIN_GetSourceLocation( di.pMergedDeadInfo->ip2, NULL, &line,&file);
        fprintf(gTraceFile,"\n%p:%s:%d",(void *)(di.pMergedDeadInfo->ip2),file.c_str(),line);
#endif //end MERGE_SAME_LINES        
        PrintFullCallingContext(di.pMergedDeadInfo->context2);
        fprintf(gTraceFile,"\n-------------------------------------------------------\n");
    }
  



// Silly: since we use these as map values, they have to be
// copy constructible. Plain arrays aren't, but structs containing
// arrays are. So we make these goofy wrappers.
struct match_strings {
    int val[MAX_STRINGS];
};

char matchfile[128] = {};
char matchfile_user[128] = {};


struct string_pos {
    uint32_t val[MAX_STRINGS];
};
struct fullstack {
    int n;
    target_ulong addr;
    target_ulong callers[MAX_CALLERS];
    target_ulong pc;
    target_ulong asid;
};

std::map<prog_point,fullstack> matchstacks;
std::map<prog_point,fullstack> matchstacks_user;
std::map<prog_point,match_strings> matches;
std::map<prog_point,string_pos> read_text_tracker;
std::map<prog_point,string_pos> write_text_tracker;
uint8_t tofind[MAX_STRINGS][MAX_STRLEN];
uint32_t strlens[MAX_STRINGS];
int num_strings = 0;
int n_callers = 16;

FILE *mem_report = NULL;
FILE *mem_report_user = NULL;

// this creates BOTH the global for this callback fn (on_ssm_func)
// and the function used by other plugins to register a fn (add_on_ssm)
//PPP_CB_BOILERPLATE(on_trace_mem_asid)

// this creates the 

int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf, bool is_write,
                       std::map<prog_point,string_pos> &text_tracker) {
    prog_point p = {};
    get_prog_point(env, &p);

//    string_pos &sp = text_tracker[p];

    if(p.cr3 == 0){

	//printf("%s\t" TARGET_FMT_lx
 	//		"\t %lu \t" TARGET_FMT_lx 
	//		"\t" TARGET_FMT_lx 
	//		"\n",
        //    (is_write ? "W" : "R"), addr, 
	//		rr_get_guest_instr_count(), p.caller,
	//		p.pc);

        // Also get the full stack here
        fullstack f = {0};
        f.n = get_callers(f.callers, n_callers, env);
        f.pc = p.pc;
        f.asid = p.cr3;


       // Print prog point
	// ORDER:
	// W/R	addr callers1 ... callersn pc asid
       	fprintf(mem_report, "%s\t", (is_write ? "W" : "R"));

       	fprintf(mem_report, TARGET_FMT_lx " ", addr);

        for (int i = f.n-1; i >= 0; i--) {
            fprintf(mem_report, TARGET_FMT_lx " ", f.callers[i]);
        }
	if (f.n == 0){
            fprintf(mem_report, "\tno callers\t");
	}

       	fprintf(mem_report, TARGET_FMT_lx " ", f.pc);
       	fprintf(mem_report, TARGET_FMT_lx " ", f.asid);
        // Print strings that matched and how many times
        fprintf(mem_report, "\n");

        // call the i-found-a-mem-access-in-asid registered callbacks here
        //PPP_RUN_CB(on_trace_mem_asid, env, pc, addr, tofind[str_idx], strlens[str_idx], is_write)

    }else{


	//printf("%s\t" TARGET_FMT_lx
 	//		"\t %lu \t" TARGET_FMT_lx 
	//		"\t" TARGET_FMT_lx 
	//		"\n",
        //    (is_write ? "W" : "R"), addr, 
	//		rr_get_guest_instr_count(), p.caller,
	//		p.pc);

        // Also get the full stack here
        fullstack f = {0};
        f.n = get_callers(f.callers, n_callers, env);
        f.pc = p.pc;
        f.asid = p.cr3;


       // Print prog point
	// ORDER:
	// W/R	addr callers1 ... callersn pc asid
       	fprintf(mem_report_user, "%s\t", (is_write ? "W" : "R"));

       	fprintf(mem_report_user, TARGET_FMT_lx " ", addr);

        for (int i = f.n-1; i >= 0; i--) {
            fprintf(mem_report_user, TARGET_FMT_lx " ", f.callers[i]);
        }
        if (f.n == 0){
                fprintf(mem_report_user, "\tno callers\t");
        }

       	fprintf(mem_report_user, TARGET_FMT_lx " ", f.pc);
       	fprintf(mem_report_user, TARGET_FMT_lx " ", f.asid);
        // Print strings that matched and how many times
        fprintf(mem_report_user, "\n");


        // call the i-found-a-mem-access-in-asid registered callbacks here
        //PPP_RUN_CB(on_trace_mem_asid, env, pc, addr, tofind[str_idx], strlens[str_idx], is_write)


    }
/********************************************
    for (unsigned int i = 0; i < size; i++) {
        uint8_t val = ((uint8_t *)buf)[i];
        for(int str_idx = 0; str_idx < num_strings; str_idx++) {
            //if (tofind[str_idx][sp.val[str_idx]] == val)
            //    sp.val[str_idx]++;
            //else
            //    sp.val[str_idx] = 0;

            if (sp.val[str_idx] == strlens[str_idx]) {
                // Victory!
                printf("%s Match of str %d at: instr_count=%lu :  " TARGET_FMT_lx " " TARGET_FMT_lx " " TARGET_FMT_lx "\n",
                       (is_write ? "WRITE" : "READ"), str_idx, rr_get_guest_instr_count(), p.caller, p.pc, p.cr3);
                matches[p].val[str_idx]++;
                sp.val[str_idx] = 0;

                // Also get the full stack here
                fullstack f = {0};
                f.n = get_callers(f.callers, n_callers, env);
                f.pc = p.pc;
                f.asid = p.cr3;
                matchstacks[p] = f;


            }
        }
    }

**************************************************/
    return 1;
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, false, read_text_tracker);

}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, true, write_text_tracker);
}


bool init_plugin(void *self) {
    panda_cb pcb;

    panda_require("callstack_instr");

    panda_arg_list *args = panda_get_args("trace_mem");

    const char *arg_str = panda_parse_string_opt(args, "asid", "", "a single asid to search for");
    size_t arg_len = strlen(arg_str);
    if (arg_len > 0) {
        memcpy(tofind[num_strings], arg_str, arg_len);
        strlens[num_strings] = arg_len;
        num_strings++;
    }

    n_callers = panda_parse_uint64_opt(args, "callers", 16, "depth of callstack for matches");
    if (n_callers > MAX_CALLERS) n_callers = MAX_CALLERS;

    const char *prefix = panda_parse_string_opt(args, "name", "", "filename containing asids to trace memory access");
    if (strlen(prefix) > 0) {
        char stringsfile[128] = {};
        sprintf(stringsfile, "%s_trace_mem_asids.txt", prefix);

        printf ("search asid file [%s]\n", stringsfile);

        std::ifstream search_strings(stringsfile);
        if (!search_strings) {
            printf("Couldn't open %s. Exiting.\n", stringsfile);
            return false;
        }

        // Format: lines of colon-separated hex chars or quoted strings, e.g.
        // 0a:1b:2c:3d:4e
        // or "string" (no newlines)
        std::string line;
        while(std::getline(search_strings, line)) {
            std::istringstream iss(line);

            if (line[0] == '"') {
                size_t len = line.size() - 2;
                memcpy(tofind[num_strings], line.substr(1, len).c_str(), len);
                strlens[num_strings] = len;
            } else {
                std::string x;
                int i = 0;
                while (std::getline(iss, x, ':')) {
                    tofind[num_strings][i++] = (uint8_t)strtoul(x.c_str(), NULL, 16);
                    if (i >= MAX_STRLEN) {
                        printf("WARN: Reached max number of characters (%d) on string %d, truncating.\n", MAX_STRLEN, num_strings);
                        break;
                    }
                }
                strlens[num_strings] = i;
            }

            printf("stringsearch: added string of length %d to search set\n", strlens[num_strings]);

            if(++num_strings >= MAX_STRINGS) {
                printf("WARN: maximum number of strings (%d) reached, will not load any more.\n", MAX_STRINGS);
                break;
            }
        }
    }

    prefix="trace_mem_test";
    sprintf(matchfile, "%s_trace_mem.txt", prefix);
    sprintf(matchfile_user, "%s_trace_mem_user.txt", prefix);
    mem_report = fopen(matchfile, "w");
    mem_report_user = fopen(matchfile_user, "w");
    if(!mem_report) {
        printf("Couldn't write report for kernel:\n");
        perror("fopen");
        return false;
    }
    if(!mem_report_user) {
        printf("Couldn't write report for user:\n");
        perror("fopen");
        return false;
    }
        // Print rw/ addr callers, pc , asid
       	fprintf(mem_report, "R/W\taddr\t\t[callers]\tpc\tasid\n");
       	fprintf(mem_report_user, "R/W\taddr\t\t[callers]\tpc\tasid\n");


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

void uninit_plugin(void *self) {

    //Lele: from deadspy continuous deadinfo
    gPreAllocatedContextBuffer = (void **) mmap(0, PRE_ALLOCATED_BUFFER_SIZE, PROT_WRITE
                     | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        // start from index 1 so that we can use 0 as empty key for the google hash table
        gCurPreAllocatedContextBufferIndex = 1;
        //DeadMap.set_empty_key(0);


    std::map<prog_point,match_strings>::iterator it;

    for(it = matches.begin(); it != matches.end(); it++) {
        // Print prog point

        // Most recent callers are returned first, so print them
        // out in reverse order
        fullstack &f = matchstacks[it->first];
        for (int i = f.n-1; i >= 0; i--) {
            fprintf(mem_report, TARGET_FMT_lx " ", f.callers[i]);
        }
        fprintf(mem_report, TARGET_FMT_lx " ", f.pc);
        fprintf(mem_report, TARGET_FMT_lx " ", f.asid);

        // Print strings that matched and how many times
        for(int i = 0; i < num_strings; i++)
            fprintf(mem_report, " %d", it->second.val[i]);
        fprintf(mem_report, "\n");
    }

    printf("\nlog writtent to %s\n", matchfile);
    printf("\nlog writtent to %s\n", matchfile_user);

    fclose(mem_report);
    fclose(mem_report_user);
}
