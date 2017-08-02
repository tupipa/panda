#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <string>
#include <algorithm>

#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <cerrno>

#include <inttypes.h>



Dwarf_Unsigned prev_line = 0, cur_line;
Dwarf_Addr prev_function = 0, cur_function;
Dwarf_Addr prev_line_pc = 0;


std::map<Dwarf_Addr,std::string> funcaddrs;

std::map<target_ulong, std::pair<Dwarf_Debug*, int>> libBaseAddr_to_debugInfo;


void load_func_from_die(Dwarf_Debug *dbg, Dwarf_Die the_die,
        const char *basename,  uint64_t base_address,uint64_t cu_base_address, bool needs_reloc){
    char* die_name = 0;
    Dwarf_Error err;
    Dwarf_Half tag;
    Dwarf_Attribute* attrs;
    Dwarf_Half attrform;
    Dwarf_Addr lowpc = 0, highpc = 0;
    Dwarf_Signed attrcount, i;
    Dwarf_Locdesc **locdesclist;
    Dwarf_Signed loccnt;

    int rc = dwarf_diename(the_die, &die_name, &err);
    if (rc == DW_DLV_ERROR){
        die("Error in dwarf_diename\n");
        return;
    } else if (rc == DW_DLV_NO_ENTRY)
        return;

    if (dwarf_tag(the_die, &tag, &err) != DW_DLV_OK) {
        die("Error in dwarf_tag\n");
        return;
    }

    /* Only interested in subprogram DIEs here */
    if (tag != DW_TAG_subprogram)
        return;

    /* Grab the DIEs attributes for display */
    if (dwarf_attrlist(the_die, &attrs, &attrcount, &err) != DW_DLV_OK)
        die("Error in dwarf_attlist\n");

    bool found_highpc = false;
    bool found_fp_info = false;
    for (i = 0; i < attrcount; ++i) {
        Dwarf_Half attrcode;
        if (dwarf_whatattr(attrs[i], &attrcode, &err) != DW_DLV_OK)
            die("Error in dwarf_whatattr\n");
        if (dwarf_whatform(attrs[i], &attrform, &err) != DW_DLV_OK)
            die("Error in dwarf_whatform\n");

        /* We only take some of the attributes for display here.
        ** More can be picked with appropriate tag constants.
        */
        if (attrcode == DW_AT_low_pc) {
            dwarf_formaddr(attrs[i], &lowpc, 0);
            // address is line of function + 1
            // in order to skip past function prologue

            //die("Error: line %d, address: 0x%llx, function %s\n", j, lowpc_before_prol, die_name);
        } else if (attrcode == DW_AT_high_pc) {
            enum Dwarf_Form_Class fc = DW_FORM_CLASS_UNKNOWN;
            Dwarf_Half theform = 0;
            Dwarf_Half directform = 0;
            Dwarf_Half version = 0;
            Dwarf_Half offset_size = 0;
            int wres = 0;

            dwarf_formaddr(attrs[i], &highpc, &err);
            if (attrform == DW_FORM_data4)
            {
                dwarf_formudata(attrs[i], &highpc, 0);
                highpc += lowpc;
            } else {
                get_form_values(attrs[i],&theform,&directform);
                wres = dwarf_get_version_of_die(the_die,&version,&offset_size);
                if (wres != DW_DLV_OK) {
                    die("Cannot get DIE context version number");
                    break;
                }
                fc = dwarf_get_form_class(version,attrcode,offset_size,theform);
                if (DW_DLV_OK != dwarf_formaddr(attrs[i], &highpc, &err)) {
                    printf("Was not able to process function [%s].  Error in getting highpc\n", die_name);
                }
                if (fc == DW_FORM_CLASS_CONSTANT) {
                    highpc += lowpc;
                }
            }

            found_highpc = true;
        } else if (attrcode == DW_AT_frame_base) {
            // get where attribute frame base attribute points
            if (-1 == get_die_loc_info(*dbg, the_die, attrcode, &locdesclist,&loccnt, base_address, cu_base_address, needs_reloc)){
                printf("Was not able to get [%s] location info for it\'s frame pointer\n", die_name);
            } else{
                found_fp_info = true;
            }
        }
    }

    if (found_highpc) {
        if (needs_reloc) {
            lowpc += base_address;
            highpc += base_address;
        }
        //functions[std::string(basename)+"!"+die_name] = std::make_pair(lowpc, highpc);
        auto lineToFuncAddress = [lowpc, highpc](LineRange &x){
            // if a line range (we just need to check its lowpc) fits between range of a function
            // we update the LineRange to reflect that the line is in the current function
            if (x.lowpc < highpc && x.lowpc >= lowpc){
                x.function_addr = lowpc;
            }
        };
        auto lineIsFunctionDef = [lowpc](LineRange &x){
            return x.lowpc == lowpc;
        };
        auto funct_line_it = std::find_if(line_range_list.begin(), line_range_list.end(), lineIsFunctionDef);

        if (funct_line_it != line_range_list.end()){
            fn_start_line_range_list.push_back(*funct_line_it);
            // add the LineRange information for the function to fn_name_to_line_info for later use
            // when resolving dwarf information for .plt functions
            // NOTE: this assumes that all function names are unique.

            fn_name_to_line_info.insert(std::make_pair(std::string(die_name),
                        LineRange(lowpc,
                            highpc,
                            funct_line_it->line_number,
                            funct_line_it->filename,
                            lowpc,
                            funct_line_it->line_off)));

            // now check if current function we are processing is in dynl_functions if so
            // point the dynl_function to this function's line number, filename, and line_off
            for (auto lib_name : processed_libs) {
                if (dynl_functions.find(lib_name + ":plt!" + std::string(die_name)) != dynl_functions.end()){
                    //printf("Trying to match function to %s\n",(lib_name + ":plt!" + std::string(die_name)).c_str());
                    Dwarf_Addr plt_addr = dynl_functions[lib_name + ":plt!" + std::string(die_name)];
                    //printf("Found it at 0x%llx, adding to line_range_list\n", plt_addr);
                    //printf(" found a plt function defintion for %s\n", basename);

                    line_range_list.push_back(LineRange(plt_addr,
                                                        plt_addr,
                                                        funct_line_it->line_number,
                                                        funct_line_it->filename,
                                                        lowpc,
                                                        funct_line_it->line_off));

                }
            }
        } else {
            printf("Could not find start of function [%s] in line number table something went wrong\n", die_name);
        }

        // this is if we want the start of the function to be one PAST the line that represents start of function
        // in order to skip past function prologue
        //if (funct_line_it != line_range_list.end()){
        //    ++funct_line_it;
        //    fn_start_line_range_list.push_back(*funct_line_it);
        //}
        std::for_each(line_range_list.begin(), line_range_list.end(), lineToFuncAddress);
        funcaddrs[lowpc] = std::string(basename) + "!" + die_name;
        // now add functions frame pointer locaiton list funct_to_framepointers mapping
        if (found_fp_info){
            funct_to_framepointers[lowpc] = std::make_pair(locdesclist, loccnt);
        } else {
            funct_to_framepointers[lowpc] = std::make_pair((Dwarf_Locdesc **)NULL, 0);
        }
    } else {
        // we are processing a function that is in the .plt so we skip it because the function
        // is either defined in a library we don't have access to or a library our dwarf processor
        // will process later (or maybe already has!)
        return;
    }
    // Load information about arguments and local variables
    //printf("Loading arguments and variables for %s\n", die_name);
    Dwarf_Die arg_child;
    std::vector<std::string> params;
    std::string argname;
    std::vector<VarInfo> var_list;
    if (dwarf_child(the_die, &arg_child, &err) != DW_DLV_OK) {
        return;
    }
    DwarfVarType *dvt;
    /* Now go over all children DIEs */
    while (arg_child != NULL) {
        if (dwarf_tag(arg_child, &tag, &err) != DW_DLV_OK) {
            die("Error in dwarf_tag\n");
            break;
        }
        switch (tag) {
            /* fall through to default case to get sibling die */
            case DW_TAG_formal_parameter:
                argname = getNameFromDie(dbg, arg_child);

                dvt = (DwarfVarType *)malloc(sizeof(DwarfVarType));
                *dvt = {*dbg, arg_child};

                if (-1 == get_die_loc_info(*dbg, arg_child, DW_AT_location, &locdesclist,&loccnt, base_address, cu_base_address, needs_reloc)){
                    // value is likely optimized out, so has no location
                    //printf("Var [%s] has no loc\n", argname.c_str());
                } else {
                    var_list.push_back(VarInfo((void *)dvt,argname,locdesclist,loccnt));
                }
                // doesn't work but if we wanted to keep track of params we
                // could do something like this
                //params.push_back(dvt, argname);
                break;
            /* fall through to default case to get sibling die */
            case DW_TAG_unspecified_parameters:
                //params.push_back("...");
                break;
            /* does NOT fall through to default case to get sibling die because gets child die */
            case DW_TAG_lexical_block:
                /* Check the Lexical block DIE for children */
                {
                    Dwarf_Die tmp_die;
                    rc = dwarf_child(arg_child, &tmp_die, &err);
                    if (rc == DW_DLV_NO_ENTRY) {
                        // no children, so skip to end of loop
                        // and get the sibling die
                        arg_child = NULL;
                        break;
                    }
                    else if (rc == DW_DLV_OK) {
                        arg_child = tmp_die;
                        // skip the dwarf_sibling code()
                        // and go to the top of while loop to collect
                        // dwarf information within the lexical block
                        continue;
                    }
                    // there is not arg_child so set it to null
                    else {
                        arg_child = NULL;
                        continue;
                    }
                }
            case DW_TAG_variable:
                argname = getNameFromDie(dbg, arg_child);

                dvt = (DwarfVarType *)malloc(sizeof(DwarfVarType));
                *dvt = {*dbg, arg_child};

                if (-1 == get_die_loc_info(*dbg, arg_child, DW_AT_location, &locdesclist,&loccnt, base_address, cu_base_address, needs_reloc)){
                    // value is likely optimized out, so has no location
                    //printf("Var [%s] has no loc\n", argname.c_str());
                } else {
                    var_list.push_back(VarInfo((void *)dvt, argname, locdesclist, loccnt));
                }
                break;
            case DW_TAG_label:
            default:
                //printf("UNKNOWN tag in function dwarf analysis\n");
                break;
        }
        rc = dwarf_siblingof(*dbg, arg_child, &arg_child, &err);

        if (rc == DW_DLV_ERROR) {
            die("Error getting sibling of DIE\n");
            arg_child = NULL;
        }
        else if (rc == DW_DLV_NO_ENTRY) {
            arg_child = NULL; /* done */
        }
    }
    //funct_to_cu_base[lowpc] = cu_base_address;
    funcvars[lowpc] = var_list;
    //funcparams[lowpc] = boost::algorithm::join(params, ", ");
    //printf(" %s #variables: %lu\n", funcaddrs[lowpc].c_str(), var_list.size());

}

bool populate_line_range_list(Dwarf_Debug *dbg, const char *basename, uint64_t base_address, bool needs_reloc) {
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Error err;
    Dwarf_Die no_die = 0, cu_die;
    /* Find compilation unit header */
    while (dwarf_next_cu_header(
                *dbg,
                &cu_header_length,
                &version_stamp,
                &abbrev_offset,
                &address_size,
                &next_cu_header,
                &err) != DW_DLV_NO_ENTRY) {
        /* Expect the CU to have a single sibling - a DIE */
        if (dwarf_siblingof(*dbg, no_die, &cu_die, &err) == DW_DLV_ERROR) {
            die("Error getting sibling of CU\n");
            continue;
        }
        Dwarf_Line *dwarf_lines;
        Dwarf_Signed line_count;

        Dwarf_Addr cu_base_address;
        Dwarf_Attribute cu_loc_attr;
        if (dwarf_attr(cu_die, DW_AT_low_pc, &cu_loc_attr, &err) != DW_DLV_OK){
            //printf("CU did not have  low pc.  Setting to 0 . . .\n");
            cu_base_address=0;
        }
        else{
            dwarf_formaddr(cu_loc_attr, &cu_base_address, 0);
            //printf("CU did have low pc 0x%llx\n", cu_base_address);
        }
        int i;
        if (DW_DLV_OK == dwarf_srclines(cu_die, &dwarf_lines, &line_count, &err)){
            char *filenm_tmp;
            char *filenm_cu;
            if (line_count > 0){
                // TODO: fix these filenames
                dwarf_linesrc(dwarf_lines[0], &filenm_cu, &err);
                //filenm_cu = (char *) malloc(strlen(filenm_tmp)+1);
                //strcpy(filenm_cu, filenm_tmp);

                for (i = 1; i < line_count; i++){
                    char *filenm_line;
                    filenm_tmp = NULL;
                    Dwarf_Addr upper_bound_addr=0, lower_bound_addr = 0;
                    Dwarf_Unsigned line_num, line_off;
                    dwarf_lineaddr(dwarf_lines[i-1], &lower_bound_addr, &err);
                    dwarf_lineaddr(dwarf_lines[i], &upper_bound_addr, &err);

                    // only continue processing the line if lower is less than
                    // upper
                    if (lower_bound_addr < upper_bound_addr) {
                        dwarf_lineno(dwarf_lines[i-1], &line_num, &err);
                        dwarf_lineoff_b(dwarf_lines[i-1], &line_off, &err);
                        dwarf_linesrc(dwarf_lines[i-1], &filenm_tmp, &err);
                        //if (!filenm_tmp || 0 == strcmp(filenm_tmp, filenm_cu)){
                        if (!filenm_tmp || *filenm_tmp == '\0') {
                            filenm_line = (char *) "(unknown filename)";
                            //filenm_line = filenm_cu;
                        } else {
                            filenm_line = filenm_tmp;
                        }
                        //if (0 == strcmp(".S", strlen(filenm_line) + filenm_line -2)) {
                        // this implicitly assumes that filenames are more than
                        // one character
                        if ('.' == filenm_line[strlen(filenm_line) - 1] &&
                            'S' == filenm_line[strlen(filenm_line) - 2]) {
                            dwarf_dealloc(*dbg, filenm_tmp, DW_DLA_STRING);
                            continue;
                        }

                        //std::vector<std::tuple<Dwarf_Addr, Dwarf_Addr, Dwarf_Unsigned, char *, Dwarf_Addr>> line_range_list;
                        if (needs_reloc) {
                            LineRange lr = LineRange(base_address+lower_bound_addr,
                                    base_address+upper_bound_addr,
                                    line_num, filenm_line, 0, line_off);
                            //std::cout << lr << "\n";
                            line_range_list.push_back(lr);
                        } else {
                            LineRange lr = LineRange(lower_bound_addr, upper_bound_addr, line_num,
                                    filenm_line, 0, line_off);
                            //std::cout << lr << "\n";
                            line_range_list.push_back(lr);
                        }
                        dwarf_dealloc(*dbg, filenm_tmp, DW_DLA_STRING);
                        //printf("line no: %lld at addr: 0x%llx\n", line_num, lower_bound_addr);
                    } else {
                        // lower bound is greater than upper bound so we skip
                        // the line block that we are processing
                    }
                }
                dwarf_dealloc(*dbg, filenm_cu, DW_DLA_STRING);
            }
            dwarf_srclines_dealloc(*dbg, dwarf_lines, line_count);
        }
        else {
            printf("Could not get get function line number\n");
        }
    }
    return true;
}


/* Load all function and globar variable info.
*/
bool load_debug_info(Dwarf_Debug *dbg, const char *basename, uint64_t base_address, bool needs_reloc) {
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Error err;
    Dwarf_Die no_die = 0, cu_die, child_die;
    int count = 0;

    populate_line_range_list(dbg, basename, base_address, needs_reloc);
    /* Find compilation unit header */
    while (dwarf_next_cu_header(
                *dbg,
                &cu_header_length,
                &version_stamp,
                &abbrev_offset,
                &address_size,
                &next_cu_header,
                &err) != DW_DLV_NO_ENTRY) {
        /* Expect the CU to have a single sibling - a DIE */
        if (dwarf_siblingof(*dbg, no_die, &cu_die, &err) == DW_DLV_ERROR) {
            die("Error getting sibling of CU\n");
            continue;
        }
        //Dwarf_Line *dwarf_lines;
        //Dwarf_Signed line_count;

        Dwarf_Addr cu_base_address;
        Dwarf_Attribute cu_loc_attr;
        if (dwarf_attr(cu_die, DW_AT_low_pc, &cu_loc_attr, &err) != DW_DLV_OK){
            //printf("CU did not have  low pc.  Setting to 0 . . .\n");
            cu_base_address=0;
        }
        else{
            dwarf_formaddr(cu_loc_attr, &cu_base_address, 0);
            //printf("CU did have low pc 0x%llx\n", cu_base_address);
        }
        int rc;
        /* Expect the CU DIE to have children */
        if ((rc = dwarf_child(cu_die, &child_die, &err)) != DW_DLV_OK) {
            if (rc == DW_DLV_ERROR)
                die("Error getting child of CU DIE\n");
            continue;
        }

        /* Now go over all children DIEs in the compilation unit */
        DwarfVarType *dvt;
        while (1) {
            std::string argname;
            Dwarf_Half tag;
            if (dwarf_tag(child_die, &tag, &err) != DW_DLV_OK)
                die("Error in dwarf_tag\n");

            if (tag == DW_TAG_subprogram){
                load_func_from_die(dbg, child_die, basename, base_address, cu_base_address, needs_reloc);
            }
            else if (tag == DW_TAG_variable){

                Dwarf_Locdesc **locdesclist=NULL;
                Dwarf_Signed loccnt;
                argname = getNameFromDie(dbg, child_die);
                dvt = (DwarfVarType *)malloc(sizeof(DwarfVarType));
                *dvt = {*dbg, child_die};
                if (-1 == get_die_loc_info(*dbg, child_die, DW_AT_location, &locdesclist,&loccnt, base_address, cu_base_address, needs_reloc)){
                    // value is likely optimized out
                    //printf("Var [%s] has no loc\n", argname.c_str());
                }
                else{
                    global_var_list.push_back(VarInfo((void *)dvt,argname,locdesclist,loccnt));
                }
            }

            rc = dwarf_siblingof(*dbg, child_die, &child_die, &err);

            if (rc == DW_DLV_ERROR) {
                die("Error getting sibling of DIE\n");
                break;
            }
            else if (rc == DW_DLV_NO_ENTRY) {
                break; /* done */
            }
        }
        count ++;
    }
    printf("Processed %d Compilation Units\n", count);
    if (count < 1 && !allow_just_plt){
         return false;
    }
    // sort the line number ranges
    std::sort(fn_start_line_range_list.begin(), fn_start_line_range_list.end(), sortRange);
    std::sort(line_range_list.begin(), line_range_list.end(), sortRange);
    printf("Successfully loaded debug symbols for %s\n", basename);
    printf("Number of address range to line mappings: %lu num globals: %lu\n", line_range_list.size(), global_var_list.size());
    return true;
}


bool read_debug_info(const char* dbgfile, const char *basename, uint64_t base_address, bool needs_reloc) {
    //std::unique_ptr<Dwarf_Debug> dbg = make_unique<Dwarf_Debug>();
    Dwarf_Debug *dbg = (Dwarf_Debug *) malloc(sizeof(Dwarf_Debug));
    Dwarf_Error err;
    int fd = -1;
    if ((fd = open(dbgfile, O_RDONLY)) < 0) {
        perror("open");
        return false;
    }

    if (dwarf_init(fd, DW_DLC_READ, 0, 0, dbg, &err) != DW_DLV_OK) {
        fprintf(stderr, "Failed DWARF initialization\n");
        return false;
    }

    if (!load_debug_info(dbg, basename, base_address, needs_reloc)){
        fprintf(stderr, "Failed DWARF loading\n");
        return false;
    }

    /* don't free dbg info anymore
    if (dwarf_finish(dbg, &err) != DW_DLV_OK) {
        fprintf(stderr, "Failed DWARF finalization\n");
        return false;
    }
    */
    //close(fd);
    //std::map<target_ulong, std::pair<Dwarf_Debug, int>> libBaseAddr_to_debugInfo;
    libBaseAddr_to_debugInfo[base_address] = std::make_pair(dbg, fd);
    return true;
}
