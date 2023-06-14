#include <stdio.h>

__attribute__((constructor))
void child() {
	printf("Hello World\n");
}
