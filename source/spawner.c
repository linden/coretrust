// derived from: https://github.com/zhuowei/CoreTrustDemo/blob/main/spawn_root.m
#include <spawn.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>

extern char** environ;

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);

int main(int argc, char *argv[]) {
	posix_spawnattr_t attributes;
	posix_spawnattr_init(&attributes);
	posix_spawnattr_set_persona_np(&attributes, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
	posix_spawnattr_set_persona_uid_np(&attributes, 0);
	posix_spawnattr_set_persona_gid_np(&attributes, 0);

	char *const arguments[3] = {
		"./main",
		argv[1],
		NULL
	};

	int pid = 0;
	int result = posix_spawnp(&pid, "./main", NULL, &attributes, arguments, environ);

	if (result) {
		printf("failed to spawn main\n");
		return 1;
	}

	waitpid(pid, NULL, 0);

	return 0;
}
