

#ifndef __TRACE_DEADWRITE_H_
#define __TRACE_DEADWRITE_H_


#define MAX_STRINGS 100
#define MAX_CALLERS 128

#define CALLERS_PER_INS 3
#define CALLERS_LAST 0
#define CALLERS_SECOND_LAST 1
#define CALLERS_THIRD_LAST 2

#define MAX_STRLEN  1024


// the type for the ppp callback fn that can be passed to string search to be called
// whenever a string match is observed
typedef void (* on_deadwrite_t)(CPUState *env, target_ulong pc, target_ulong addr,
			  uint8_t *matched_string, uint32_t matched_string_lenght, 
			  bool is_write);


#endif
