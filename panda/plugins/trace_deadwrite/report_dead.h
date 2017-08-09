
#ifndef __REPORT_DEAD_H_
#define __REPORT_DEAD_H_

#include "trace_deadwrite.h"


int addr2line(std::string debugfile, target_ulong addr, FileLineInfo * lineInfo);

/* 
for kernel modules, convert pc according to offset/size info, and call addr2line
*/
int addr2line_wrap(DebugFile &dbgf, target_ulong addr, FileLineInfo * lineInfo);



/* searchDebugFilesForProcName:
    - for asid with IP, search all debugfiles that can return the lineInfo for this ip.
    - debug files stored in a vector of strings
    - mark the gProcToDebugDone[procName] as done if found one available lineInfo from a file.
    - TODO: might be other ways to find debugfiles for a procName,
    -    e.g. list in the txt file statically, or search here more intelligently
*/
int searchDebugFilesForProcName(std::string procName, target_ulong ip, FileLineInfo *fileInfo);


/* getLineInfoForAsidIP:

    - given asid, and ip, trying to find proper debug file and call addr2line to get the line info

    - here we create and maintain a debug file vector for each asid <-> debugfiles 

*/

int getLineInfoForAsidIP(target_ulong asid_target, target_ulong ip, FileLineInfo *fileInfo);


// Given a context node (curContext), traverses up in the chain till the root and prints the entire calling context 

VOID PrintFullCallingContext(ContextNode * curContext);

// Given the DeadInfo data, prints the two Calling contexts
VOID PrintCallingContexts(const DeadInfo & di);


inline VOID PrintInstructionBreakdown();


#ifdef GATHER_STATS
    inline void PrintStats(
#ifdef IP_AND_CCT
                           std::list<DeadInfoForPresentation> & deadList,
#else // no IP_AND_CCT
                           std::list<DeadInfo> & deadList,
#endif  // end IP_AND_CCT
                           target_ulong deads);
#endif // GATHER_STATS


inline target_ulong GetMeasurementBaseCount();



// Prints the collected statistics on writes along with their sizes
inline void PrintEachSizeWrite();


inline ADDRINT GetIPFromInfo(void * ptr);


// Given a pointer (i.e. slot) within a trace node, returns the Line number corresponding to that slot
inline std::string GetLineFromInfo(void * ptr);

void  panda_GetSourceLocation(ADDRINT ip, unsigned long *line, std::string *file, std::string *func);


// Prints the complete calling context including the line nunbers and the context's contribution, given a DeadInfo 
inline VOID PrintIPAndCallingContexts(const DeadInfoForPresentation & di, target_ulong measurementBaseCount);



    // On each Unload of a loaded image, the accummulated deadness information is dumped
// VOID ImageUnload() {
void ExtractDeadMap();


// On program termination output all gathered data and statistics
// VOID Fini(int32_t code, VOID * v) {
VOID Fini();


inline void printRunningProcs();

VOID printAllProcsFound();

void  panda_GetSourceLocation(ADDRINT ip, unsigned long *line, std::string *file, std::string *func);

#endif