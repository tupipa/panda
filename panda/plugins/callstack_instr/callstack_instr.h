#ifndef __CALLSTACK_INSTR_H
#define __CALLSTACK_INSTR_H

#include "prog_point.h"

typedef void (* on_call_t)(CPUState *env,  target_ulong dst_func);
typedef void (* on_ret_t)(CPUState *env, target_ulong from_func);

typedef void (* on_call2_t)(CPUState *env, TranslationBlock *src_tb, target_ulong dst_func);
typedef void (* on_ret2_t)(CPUState *env, TranslationBlock *dst_tb, target_ulong from_func);

#endif
