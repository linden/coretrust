// derived from: http://newosxbook.com/src.jl?tree=listings&file=inject.c

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

#define STACK_SIZE 65536
#define CODE_SIZE 128

char injected[] =
	// That's the ARM64 "shellcode"
	"\x08\x03\x00\x58" // LDR X8, #3 ; load PTHREADSS
	"\x00\x01\x3f\xd6" // BLR X8     ; do pthread_set_self
	
	 "\x00\x01\x00\x10" // ADR X0, #32
	"\x00\x40\x01\x91"  // ADD x0, x0, #0x50  ; X0 => "LIBLIBLIB...";
	"\x08\x03\x00\x58"  // LDR X8, #3 ; load DLOPEN
	"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
	"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
	// dlopen("LIBLIBLIB", 0);
	"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()
	"\xa8\x00\x00\x58"  // LDR X8, #12 ; load PTHREADEXT
	"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
	"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit
	"\x00\x00\x20\xd4"  // BRK X0     ; // useful if you need a break :)
	"XXXX" 
	"PTHRDEXT"   // <-
	"AAAA"
	"BCDEFGHI"
	"JKLMNOPR"
	"STUVWXYZ"
	"!!!!!!!!"
	"_PTHRDSS"  // <-
	"PTHRDEXT"  //
	"DLOPEN__"  // <- 
	"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB" 
	"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
	"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
	"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
	"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
	"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00";

int main(int argc, char *argv[]) {
	int pid = atoi(argv[1]);

	mach_port_name_t task;
	kern_return_t result = task_for_pid(mach_task_self(), pid, &task);

	if (result != KERN_SUCCESS) {
		printf("failed to get task for pid: %s\n", mach_error_string(result));
		return 1;
	}

	mach_vm_address_t stack = (vm_address_t) NULL;

	result = mach_vm_allocate(task, &stack, STACK_SIZE, VM_FLAGS_ANYWHERE);

	if (result != KERN_SUCCESS) {
		printf("failed to allocate memory for remote stack: %s\n", mach_error_string(result));
		return 1;
	}

	mach_vm_address_t code = (vm_address_t) NULL;

	result = mach_vm_allocate(task, &code, CODE_SIZE, VM_FLAGS_ANYWHERE);

	if (result != KERN_SUCCESS) {
		printf("failed to allocate memory for remote code: %s\n", mach_error_string(result));
		return 1;
	}

	int index = 0;
	char *patch = (injected);

	for (index = 0; index < 0x100; index++) {
		extern void *_pthread_set_self;
		patch++;

		uint64_t address_pthread_set_self = (uint64_t)dlsym(RTLD_DEFAULT, "_pthread_set_self");
		uint64_t address_pthread_exit = (uint64_t)dlsym(RTLD_DEFAULT, "pthread_exit");
		uint64_t address_dlopen = (uint64_t)dlopen;
		uint64_t address_sleep = (uint64_t)sleep;

		if (strcmp(patch, "PTHRDEXT") == 0) {
			memcpy(patch, &address_pthread_exit, 8);

			printf("pthread exit 0x%llx\n", address_pthread_exit);
		}

		if (strcmp(patch, "_PTHRDSS") == 0) {
			memcpy(patch, &address_pthread_set_self, 8);

			printf("pthread set self 0x%llx\n", address_pthread_set_self);
		}

		if (strcmp(patch, "DLOPEN__") == 0) {
			printf("dlopen 0x%llx\n", address_dlopen);
			memcpy(patch, &address_dlopen, sizeof(uint64_t));
		}

		if (strcmp(patch, "SLEEP___") == 0) {
			printf("sleep 0x%llx\n", address_sleep);
			memcpy(patch, &address_sleep, sizeof(uint64_t));
		}

		if (strcmp(patch, "LIBLIBLIB") == 0) {
			strcpy(patch, "./child.dylib");
		}
  	}

  	result = mach_vm_write(task, code, (vm_address_t) injected, 0xa9);

	if (result != KERN_SUCCESS) {
		printf("failed to inject contents of remote code: %s\n", mach_error_string(result));
		return 1;
	}

	result  = vm_protect(task, code, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

	if (result != KERN_SUCCESS) {
		printf("failed to mark code as executable: %s\n", mach_error_string(result));
		return 1;
	}

	result = vm_protect(task, stack, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);
	
	if (result != KERN_SUCCESS) {
		printf("failed to mark stack as writable: %s\n", mach_error_string(result));
		return 1;
	}

	stack += (STACK_SIZE / 2);

	arm_thread_state64_t state;
	arm_thread_state64_set_pc_fptr(state, code);
	arm_thread_state64_set_sp(state, stack);

	thread_t thread;

	result = thread_create_running(task, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT, &thread);

	if (result != KERN_SUCCESS) {
		printf("failed to create remote thread: %s\n", mach_error_string(result));
		return 1;
	}

	return 0;
}

// https://sourcegraph.com/github.com/apple-oss-distributions/dyld/-/blob/include/mach-o/dyld_process_info.h?L40
