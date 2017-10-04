#include <stdlib.h>
#include <sys/mman.h>

int main() {
	return mincore(0, 0xffffffffffff0000, NULL);
}
