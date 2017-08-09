
#include "report_dead.h"

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

    // printf("%s: cmd returned: '%s'\n", __FUNCTION__, rawLineInfo.c_str());

    if (rawLineInfo.find("?? ??:0") != std::string::npos){
        printf("%s: No result from addr2line: %s\n",__FUNCTION__, rawLineInfo.c_str());
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

    }else if (rawLineInfo.find(":?") != std::string::npos){
        // printf("have func and file, but no line result from addr2line\n");

        printf("get addr2line result:\n\t%s\n\tnow parse it\n", rawLineInfo.c_str());
        //parse and store it as FileLineInfo struct.
        size_t pos = rawLineInfo.find(" ");
        lineInfo->funName = rawLineInfo.substr(0,pos); //store fun name.

        std::string tmp = rawLineInfo.substr(pos+1); // ignore fun name and space.
        std::cout<<"rest raw after ignore func: "<<tmp<<std::endl;
        
        //find second space, must be after 'at'
        pos = tmp.find(" ");
        tmp = tmp.substr(pos+1); //ignore 'at' and space
        std::cout<<"rest raw after ignore 'at': "<<tmp<<std::endl;

        pos = tmp.find(":");
        lineInfo->fileName = tmp.substr(0, pos);
        tmp = tmp.substr(pos+1); //ignore file name and :
        std::cout<<"rest raw after ignore 'filename': "<<tmp<<std::endl;

        pos = tmp.find("?");

        lineInfo->lineNum = 0;

        if (pos + 1 != tmp.length()){
            tmp = rawLineInfo.substr(pos+1); //ignore line Num '?'.
            lineInfo->extraInfo = tmp;
        }else{
            lineInfo->extraInfo = "";
        }

        lineInfo->valid = true;


    }else if (rawLineInfo.find_first_not_of("\n\t ") != std::string::npos){
        // not empty string.

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
            tmp = tmp.substr(pos); //ignore line Num.
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


/* 
for kernel modules, convert pc according to offset/size info, and call addr2line
*/
int addr2line_wrap(DebugFile &dbgf, target_ulong addr, FileLineInfo * lineInfo){

    if(dbgf.isKernel){
    
    	if(dbgf.offset == 0){
    		printf("%s: ERROR: kernel module offset is 0. file name: %s\n", 
    			__FUNCTION__, dbgf.filename.c_str());
    	    exit(-1);
    	}
		//target_ulong offset = dbgf.offset;
		//target_ulong size = dbgf.size;
		
		target_ulong vaddr = addr - dbgf.offset;
		
		printf("\n");

		if (vaddr < dbgf.size){
			// virtual address is inside the module address space.
			printf("%s: good. search inside a kernel module: %s\n", __FUNCTION__, dbgf.filename.c_str());
			return addr2line(dbgf.filename, vaddr, lineInfo);
		}else {
			//virtual address is outside the module address space.
			printf("%s: addr 0x" TARGET_FMT_lx "(vaddr: 0x" TARGET_FMT_lx ") is not in the module %s\n",
				__FUNCTION__, addr, vaddr, dbgf.filename.c_str());
			return -1;
		}
    }else{
    
    	return addr2line (dbgf.filename, addr, lineInfo);
    
    }
    
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
    // if (gTargetIsKernelMod){
    for (std::vector<std::string>::size_type i = 0; i < gDebugFiles.size(); i++){
        if (addr2line_wrap(gDebugFiles[i], ip, fileInfo) == 0){
            // found info from debugfile
            // link this debugfile with procName
            gProcToDebugFileIndex[procName] = (int) i;
            printf("%s: found kernel debug file %s for proc %s\n", __FUNCTION__, gDebugFiles[i].filename.c_str(), procName.c_str() );
            gProcToDebugDone[procName]=true;
            //exit(-1);
            return 0;
        }
    }
    // }else{
		// for (std::vector<std::string>::size_type i = 0; i < gDebugFiles.size(); i++){
		//     if (addr2line_wrap(gDebugFiles[i], ip, fileInfo) == 0){
		//         // found info from debugfile
		//         // link this debugfile with procName
		//         gProcToDebugFileIndex[procName] = (int) i;
		//         printf("%s: found debug file %s for proc %s\n", __FUNCTION__, gDebugFiles[i].c_str(), procName.c_str() );
		//         gProcToDebugDone[procName]=true;
		//         return 0;
		//     }
		// }

	// }
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
        // printf("%s: found proc name %s, for asid 0x" TARGET_FMT_lx "\n", __FUNCTION__, procName.c_str(), asid_target);

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
        debugFileName = gDebugFiles[gProcToDebugFileIndex[procName]].filename;
        // printf("%s: found debug file for %s: %s\n", __FUNCTION__, procName.c_str(), debugFileName.c_str());
        // exit(-1);

    }else{
        //no proc name found for asid: 
        // try to search it if never searched.
        // TODO: might give more chances to search? like 5 chances each procName?
        
        if (! gProcToDebugDone[procName]){
           return searchDebugFilesForProcName(procName,ip,fileInfo);
        }
        // 
        printf("%s: no debug file found for proc name: %s, with pc: 0x" TARGET_FMT_lx "\n", 
        	__FUNCTION__, procName.c_str(), ip );
        return -1;
    }

    //3, iterate through the debug file for proc.
    // TODO: might be different debug file for a proc?
    // Now only 1 debug file for the proc.

    DebugFile dbf=gDebugFiles[gProcToDebugFileIndex[procName]];
    if ( addr2line_wrap(dbf, ip, fileInfo) == 0 ){
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

        fprintf(gTraceFile, "\tcall stack:\n");
        fprintf(gTraceFile, "\tdepth\t||\tpc\t\t\t||\tsrcInfo\t\n");
        while(curContext && (depth ++ < MAX_CCT_PRINT_DEPTH )){     
            target_ulong con_pc = curContext->address;       
            if(IsValidIP(con_pc)){
                fprintf(gTraceFile, "\t-> %d\t||\t0x" TARGET_FMT_lx "\t||", 
                    depth, con_pc);
                std::string file, func;
                unsigned long line;
                //printf("get source location\n");
                panda_GetSourceLocation(con_pc,  &line, &file, &func);

                if (file == SRC_FILE_NA){
                    // ignore the call stack layer if no file info available.
                    fprintf(gTraceFile, "\tNA\n");
                }else{
                    fprintf(gTraceFile,"\t%s:%lu: %s\n",file.c_str(),line, func.c_str());
                }                          

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
                fprintf(gTraceFile, "ROOT_CTXT\n");	
            }
#else //MULTI_THREADED
            else if ( (root=IsARootContextNode(curContext)) != -1){
                fprintf(gTraceFile, "ROOT_CTXT_THREAD %d\n", root);	
            } 
#endif //end  ifndef MULTI_THREADED            
            else if (curContext->address == 0){
                fprintf(gTraceFile, "IND CALL\n");	
            } else{
                fprintf(gTraceFile, "BAD IP \n");	
            }
            curContext = curContext->parent;
        }
        //reset sig handler
        //sigaction(SIGSEGV,&old,0);
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
            lineForPc->valid = false;
            lineForPc->lineNum = 0;
            lineForPc->fileName= SRC_FILE_NA;
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
        // printf("now in func: %s\n", __FUNCTION__);
        fprintf(gTraceFile,"\n----------------------------------------\n");
        fprintf(gTraceFile,"\ncount(percentage): " TARGET_FMT_lu " (%e)\n",di.count, di.count * 100.0 / measurementBaseCount);
// #ifdef MERGE_SAME_LINES
//         fprintf(gTraceFile,"\n%s",di.pMergedDeadInfo->line1.c_str());                                    
// #else // no MERGE_SAME_LINES
        std::string file, func;
        unsigned long line;
        //printf("get source location\n");
        panda_GetSourceLocation(di.pMergedDeadInfo->ip1,  &line,&file, &func);
        fprintf(gTraceFile,"<dead write>\n");
        fprintf(gTraceFile,"  pc:%p, at %s:%lu: %s\n",(void *)(uintptr_t)(di.pMergedDeadInfo->ip1),file.c_str(),line, func.c_str());                                    
// #endif //end MERGE_SAME_LINES        
        PrintFullCallingContext(di.pMergedDeadInfo->context1);
        fprintf(gTraceFile,"\n<killing write:> \n");
// #ifdef MERGE_SAME_LINES
//         fprintf(gTraceFile,"\n%s",di.pMergedDeadInfo->line2.c_str());                                    
// #else //no MERGE_SAME_LINES        
        panda_GetSourceLocation(di.pMergedDeadInfo->ip2,  &line,&file, &func);
        fprintf(gTraceFile,"  pc: %p, at %s:%lu: %s\n",(void *)(uintptr_t)(di.pMergedDeadInfo->ip2),file.c_str(),line, func.c_str());
// #endif //end MERGE_SAME_LINES        
        PrintFullCallingContext(di.pMergedDeadInfo->context2);
        fprintf(gTraceFile,"----------------------------------------\n");

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
//     // On each Unload of a loaded image, the accummulated deadness information is dumped (JUST the CCT case, no IP)
//     // VOID ImageUnload() {
// void ExtractDeadMap(){
//         // fprintf(gTraceFile, "\nUnloading %s", IMG_Name(img).c_str());
//         fprintf(gTraceFile, "\nUnloading");
//         //static bool done = false;
//         bool done = false;
//         //if (done)
//         //    return;
        
//         //if(IMG_Name(img) != "/opt/apps/openmpi/1.3.3-gcc/lib/openmpi/mca_osc_rdma.so")
//         //if(IMG_Name(img) != "/users/mc29/mpi_dead/Gauss.exe")
//         //if(IMG_Name(img) != "/users/mc29/chombo/chombo/Chombo-4.petascale/trunk/benchmark/AMRGodunovFBS/exec/amrGodunov3d.Linux.64.mpicxx.mpif90.OPTHIGH.MPI.ex")
//         //return;
        
//         // get  measurementBaseCount first 
//         target_ulong measurementBaseCount =  GetMeasurementBaseCount();         
//         fprintf(gTraceFile, "\nTotal Instr =  " TARGET_FMT_lu "", measurementBaseCount);
//         printf("get total Instr:  " TARGET_FMT_lu "\n", measurementBaseCount);
//         fflush(gTraceFile);
        
// #if defined(CONTINUOUS_DEADINFO)
//         std::tr1::unordered_map<uint64_t, uint64_t>::iterator mapIt;
//         //dense_hash_map<uint64_t, uint64_t>::iterator mapIt;
//         //sparse_hash_map<uint64_t, uint64_t>::iterator mapIt;
// #else // no defined(CONTINUOUS_DEADINFO)        
//         dense_hash_map<uint64_t, DeadInfo>::iterator mapIt;
//         //std::tr1::unordered_map<uint64_t, DeadInfo>::iterator mapIt;
// #endif  //end defined(CONTINUOUS_DEADINFO)        
//         std::list<DeadInfo> deadList;
        
        
// #if defined(CONTINUOUS_DEADINFO)
//         for (mapIt = DeadMap.begin(); mapIt != DeadMap.end(); mapIt++) {
//             uint64_t = mapIt->first;
//             uint64_t elt1 = (hash >> 32) * sizeof(void **) / sizeof(ContextNode);
//             uint64_t elt2 = (hash & 0xffffffff) * sizeof(void **) / sizeof(ContextNode);
//             void ** ctxt1 = (void**) ((ContextNode*)gPreAllocatedContextBuffer + elt1);
//             void ** ctxt2 = (void**)((ContextNode*)gPreAllocatedContextBuffer + elt2);
//             DeadInfo tmpDeadInfo = {(void*)ctxt1, (void*)ctxt2,  mapIt->second};
//             deadList.push_back(tmpDeadInfo);
//         }
//         DeadMap.clear();
        
// #else   // no defined(CONTINUOUS_DEADINFO)        
//         for (mapIt = DeadMap.begin(); mapIt != DeadMap.end(); mapIt++) {
//             deadList.push_back(mapIt->second);
//         }
//         DeadMap.clear();
// #endif  // end defined(CONTINUOUS_DEADINFO)        
//         deadList.sort(DeadInfoComparer);
//         std::list<DeadInfo>::iterator it = deadList.begin();
//         PIN_LockClient();
//         target_ulong deads = 0;
//         for (; it != deadList.end(); it++) {
            
// #ifdef MULTI_THREADED
//             // for MT, if they are from the same CCT, skip
//             if(IsSameContextTree((ContextNode*) it->firstIP, (ContextNode*)it->secondIP)){
//             	gTotalDead += it->count ;
//                 continue;
//             } 
// #endif //end MULTI_THREADED            
            
//             // Print just first MAX_DEAD_CONTEXTS_TO_LOG contexts
//             if(deads < MAX_DEAD_CONTEXTS_TO_LOG){
//                 try{
//                     fprintf(gTraceFile,"\n " TARGET_FMT_lu " = %e",it->count, it->count * 100.0 / measurementBaseCount);
//                     PrintCallingContexts(*it);
//                 } catch (...) {
//                     fprintf(gTraceFile,"\nexcept");
//                 }
//             } else {
// #ifdef PRINT_ALL_CTXT
//                 // print only dead count
//                 fprintf(gTraceFile,"\nCTXT_DEAD_CNT: " TARGET_FMT_lu " = %e",it->count, it->count * 100.0 / measurementBaseCount);
// #endif //end PRINT_ALL_CTXT                
//             }
            
// #ifdef MULTI_THREADED
//             gTotalMTDead += it->count ;
// #endif //end MULTI_THREADED            
//             gTotalDead += it->count ;
//             deads++;
//         }
        
//         PrintEachSizeWrite();
        
        
// #ifdef TESTING_BYTES
//         PrintInstructionBreakdown();
// #endif //end TESTING_BYTES        
        
// #ifdef GATHER_STATS
//         PrintStats(deadList, deads);
// #endif //end GATHER_STATS        
        
//         deadList.clear();
//         // PIN_UnlockClient();
//         done = true;
//         printf("%s: done.\n", __FUNCTION__);
//     }

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

inline void printRunningProcs(){
    // std::unordered_set<ProcID>::iterator it;
    std::set<ProcID>::iterator it;
    for (it = gRunningProcs.begin(); it != gRunningProcs.end(); ++it)
    {
        // u_long f = *it; // Note the "*" here
		//printf("\t0x" TARGET_FMT_lx ":\t pid/ppid: " TARGET_FMT_lu "/" TARGET_FMT_lu ",\tprocName: %s, \n", 
        //    it->proc->asid, it->proc->pid, it->proc->ppid, it->proc->name);
        print_proc_info(it->proc);
    }
    printf("\n");
}
VOID printAllProcsFound(){
    // Iterate Over the Unordered Set and display it
    printf("%s: All Procs Found Running:\n", __FUNCTION__);
    printRunningProcs();

    printf("%s: (last) monitored ASID:\n", __FUNCTION__);
    if (gAsidToProcIndex.count(gTargetAsid) != 0 ){
        OsiProc *tproc=gProcIDs[gAsidToProcIndex[gTargetAsid]].proc;
        printf("\t0x" TARGET_FMT_lx ":\t pid/ppid: " TARGET_FMT_lu "/" TARGET_FMT_lu ",\tprocName: %s\n",
         gTargetAsid, tproc->pid, tproc->ppid, tproc->name);
    }
    if (gAsidToProcIndex.count(gTargetAsid_struct) != 0){
        OsiProc *tp = gProcIDs[gAsidToProcIndex[gTargetAsid_struct]].proc;
        printf("\t(struct): 0x" TARGET_FMT_lx ":\t pid/ppid: " TARGET_FMT_lu "/" TARGET_FMT_lu ",\tprocName: %s\n", 
        gTargetAsid, tp->pid, tp->ppid, tp->name);
    }
    
    // print modules for target proc
    if (gModuleIDs.size()>0){
    	printf("modules found for programs:");
    	for (int i = 0;i<gModuleIDs.size(); i++){
    		print_mod_info(&gModuleIDs[i]);
    		printf("------\n");
    	}
    }
    if (gAsidToProcIndex.count(gTargetAsid_struct) == 0 && gAsidToProcIndex.count(gTargetAsid) == 0 ){
        printf("\t no proc found for 0x" TARGET_FMT_lx ", (struct): 0x" TARGET_FMT_lx "\n", gTargetAsid, gTargetAsid_struct);
    }
}
// done last step: printing
