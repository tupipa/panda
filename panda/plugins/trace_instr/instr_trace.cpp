#include "../syscalls2/gen_syscalls_ext_typedefs.h"
#include "../syscalls2/syscalls_common.h"
#include "panda_plugin_plugin.h"


/*
void my_NtReadFile_enter(
        CPUState* env,
        target_ulong pc,
        uint32_t FileHandle,
        uint32_t Event,
        uint32_t UserApcRoutine,
        uint32_t UserApcContext,
        uint32_t IoStatusBlock,
        uint32_t Buffer,
        uint32_t BufferLength,
        uint32_t ByteOffset,
        uint32_t Key) {
   printf("NtReadFile(FileHandle=%x, Event=%x, UserApcRoutine=%x, "
                     "UserApcContext=%x, IoStatusBlock=%x, Buffer=%x, "
                     "BufferLength=%x, ByteOffset=%x, Key=%x)\n",
        FileHandle, Event, UserApcRoutine, UserApcContext,
        IoStatusBlock, Buffer, BufferLength, ByteOffset, Key);
}

// ...

bool init_plugin(void *self) {
    PPP_REG_CB("syscalls2", on_NtReadFile_enter, my_NtReadFile_enter);
    return true;
}
*/


void my_linuxsys_enter(
	CPUState *cpu, 
	target_ulong pc, 
	target_ulong callno
	) {
   printf("on_all_sys_enter(cpu, pc=%x,"
                     "callno=%x"
                     ")\n",
        pc,callno);
}

// ...

bool init_plugin(void *self) {
    PPP_REG_CB("syscalls2", on_all_sys_enter_t, my_linuxsys_enter);
    return true;
}

void uninit_plugin(void *self){

}
// ...

// ...

