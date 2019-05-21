#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>

#define SCALE_FACTOR 1

/* Portable definition of rand() from ISO/IEC 9899:1990 C standard */
static uint32_t next = 1;
int prand(void) { // RAND_MAX assumed to be 32767
	// The period is 2^31 due to the choice of 1103515245
    next = next * 1103515245 + 12345;
    return (uint32_t)(next/65536) % 32768;
}
void psrand(uint32_t seed) {
    next = seed;
}

int *get_state(int p1, int p2) {
	long long s = 0;
	int cnt = 0;
	int *ptr = malloc(sizeof(int) * 256);
	memset(ptr, 0, sizeof(int) * 256); // 0 the buffer
	for(int i = 0; i < 65536*SCALE_FACTOR && cnt < 256; i++) {
		s = p1*65536 + i;
		psrand(s); // Seed the PRNG
		if(prand() == p2) // Check second prime
			ptr[cnt++] = s; // Add potential state
	}
	return ptr;
}

int main(void) {
	srand(time(0)); // Guarantee different results each run
	int s = rand(); // Get a seed for our PRNG
	printf("The seed is %d\n", s);

	psrand( s ); // Seed our RNG
	
	// Get consecutive 2 numbers
	int p1 = prand();
	printf("State is %d\n", next);
	int p2 = prand();
	
	int *ptr = get_state(p1, p2);
	for(int i = 0; i < 256 && ptr[i] != 0; i++) {
		printf("Found potential state %d\n", ptr[i]);
	}
	free(ptr);
}
